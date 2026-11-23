#![cfg_attr(windows, windows_subsystem = "windows")]
use authorization_a_template::{current_runtime::{self,Binding,DesktopHost},WebViewRenderer,WebViewAcceptance};
use serde_json::json;
use std::{env,io::{BufRead,Write},path::PathBuf,sync::{Arc,Mutex}};

fn main(){if let Err(e)=run(){
    let args:Vec<String>=env::args().collect();
    if let Some(path)=args.iter().position(|v|v=="--receipt").and_then(|n|args.get(n+1)) {let _=std::fs::write(path,json!({"startup_error":e}).to_string());}
    #[cfg(windows)] if !args.iter().any(|v|v.starts_with("--acceptance-")) {unsafe {
        #[link(name="user32")] unsafe extern "system" {fn MessageBoxW(window:*mut std::ffi::c_void,text:*const u16,title:*const u16,flags:u32)->i32;}
        let message:Vec<u16>=format!("授权启动器无法启动，请核对软件配置。\n{e}").encode_utf16().chain(Some(0)).collect();
        let title:Vec<u16>="软件授权".encode_utf16().chain(Some(0)).collect();
        MessageBoxW(std::ptr::null_mut(),message.as_ptr(),title.as_ptr(),0x10);
    }}
    eprintln!("Launcher unavailable: {e}");std::process::exit(1);
}}
fn run()->Result<(),String>{
    let args:Vec<String>=env::args().collect();
    let flag=|name:&str| args.iter().any(|v|v==name);
    let arg=|name:&str|args.iter().position(|v|v==name).and_then(|n|args.get(n+1)).cloned().ok_or_else(||format!("Required {name}"));
    let folder=PathBuf::from(arg("--binding")?);
    let version=arg("--version")?;let installation=arg("--installation")?;
    let binding=Binding::load(&folder,&version)?;
    let scope=format!("{}|{}",folder.canonicalize().map_err(|_|"Binding path")?.display(),installation);
    let key=current_runtime::device_key(&PathBuf::from(arg("--device-key")?),&scope)?;
    let host=Arc::new(Mutex::new(DesktopHost::new(binding,installation,key)?));
    let endpoint=current_runtime::serve_local(host.clone())?;
    if flag("--acceptance-webview") {
        let script=std::fs::read_to_string(arg("--acceptance-webview")?).map_err(|_|"Missing local acceptance script")?;
        return WebViewRenderer::run_live_acceptance(host,WebViewAcceptance{script,receipt:PathBuf::from(arg("--receipt")?)}).map_err(|e|e.to_string());
    }
    if flag("--acceptance-stdio") {
        #[cfg(windows)] unsafe {
            // GUI-subsystem programs have no CRT stdio by default. Open only
            // the inherited test pipes; never allocate a visible console.
            #[link(name="kernel32")] unsafe extern "system" {fn GetStdHandle(n:u32)->*mut std::ffi::c_void;}
            use std::os::windows::io::FromRawHandle;
            let input=std::fs::File::from_raw_handle(GetStdHandle((-10i32) as u32));
            let output=std::fs::File::from_raw_handle(GetStdHandle((-11i32) as u32));
            return control_loop(host,endpoint,std::io::BufReader::new(input),output);
        }
        #[cfg(not(windows))]
        return control_loop(host,endpoint,std::io::stdin().lock(),std::io::stdout());
    }
    let core=Some(PathBuf::from(arg("--core")?));
    if let Some(path)=&core {if !path.is_absolute() || !path.is_file(){return Err("Core must be an existing absolute target path".into());}}
    let child=Arc::new(Mutex::new(None::<std::process::Child>));
    let watched=child.clone();let checked=host.lock().map_err(|_|"Host unavailable")?.deadline_monitor();
    std::thread::spawn(move ||{loop{
        std::thread::sleep(std::time::Duration::from_millis(250));
        let deadline=checked.deadline().unwrap_or_else(std::time::Instant::now);
        if std::time::Instant::now()>=deadline {if let Ok(mut child)=watched.lock(){if let Some(mut process)=child.take(){let _=process.kill();let _=process.wait();}}}
    }});
    let launch_host=host.clone();
    let launch=move |permit|{
        if !launch_host.lock().map(|host|host.permit_still_valid(&permit)).unwrap_or(false) {return;}
        if let Some(path)=&core {
            let result=std::process::Command::new(path).env("AUTHORIZATION_A_LOCAL_URL",&endpoint.address)
                .env("AUTHORIZATION_A_BOOTSTRAP_TOKEN",&endpoint.bootstrap_token).env("AUTHORIZATION_A_LOCAL_PUBLIC_KEY",&endpoint.public_key)
                .current_dir(path.parent().unwrap()).spawn();
            if let Ok(process)=result {if let Ok(mut slot)=child.lock(){*slot=Some(process);}}
        }
    };
    if flag("--acceptance-core") {
        let script=std::fs::read_to_string(arg("--acceptance-core")?).map_err(|_|"Missing local acceptance script")?;
        WebViewRenderer::run_live_core_acceptance(host,launch,WebViewAcceptance{script,receipt:PathBuf::from(arg("--receipt")?)}).map_err(|e|e.to_string())
    } else {WebViewRenderer::run_live(host,launch).map_err(|e|e.to_string())}
}
fn control_loop(host:Arc<Mutex<DesktopHost>>,endpoint:current_runtime::LocalEndpoint,input:impl BufRead,mut output:impl Write)->Result<(),String>{
        // Explicit acceptance channel uses the same host and permissions.
        for line in input.lines(){
            let line=line.map_err(|_|"Control channel closed")?;
            let command=current_runtime::parse_json(line.as_bytes())?;
            if command["op"]=="local_endpoint" {
                writeln!(output,"{}",json!({"address":endpoint.address,"bootstrap":endpoint.bootstrap_token,"public_key":endpoint.public_key})).map_err(|_|"Control write")?;
                output.flush().map_err(|_|"Control write")?;continue;
            }
            let mut h=host.lock().map_err(|_|"Host unavailable")?;
            let result=match command["op"].as_str(){
                Some("verify")=>h.verify(),Some("deactivate")=>h.deactivate(),Some("tick")=>{h.tick();Ok(())},
                Some("local")=>{let envelope=h.local_envelope();writeln!(output,"{}",json!({"local":envelope.ok(),"public_key":h.local_public_key()})).map_err(|_|"Control write")?;output.flush().map_err(|_|"Control write")?;continue;},
                Some("snapshot")=>Ok(()),_=>h.dispatch(&command)
            };
            let permit=h.take_launch_permit().map(|p|json!({"ticket_id":p.ticket_id,"authorization_id":p.authorization_id}));
            writeln!(output,"{}",json!({"ok":result.is_ok(),"error":result.err(),"render":h.snapshot(),"timing":h.timing_receipt(),"permit":permit})).map_err(|_|"Control write")?;
            output.flush().map_err(|_|"Control write")?;
        }
    Ok(())
}
