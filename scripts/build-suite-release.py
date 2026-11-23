"""Create source-only, hash-inventoried releases. Never copies runtime directories."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]
PRIVATE={'.git','.codex','.impeccable','.reverse-fusion','.venv','venv','node_modules','__pycache__','data','test-results','staticfiles','TEMP','temp','output','storage','终审清理保险','灾备钥匙包','target','历史参考'}


def source_files():
    raw=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT)
    result=[]
    for name in sorted(set(v.decode('utf-8') for v in raw.split(b'\0') if v)):
        relative=Path(name);path=ROOT/relative
        if any(part in PRIVATE for part in relative.parts) or not path.is_file():continue
        if path.is_symlink():raise ValueError('Redirected source refused: '+name)
        if relative.name.startswith('.env') and relative.name!='.env.example':continue
        if relative.suffix in {'.enc','.sqlite3','.sqlite','.db','.zip','.pem','.key','.log','.pyc'}:continue
        if relative.parts[0]=='部署与恢复' and relative.suffix!='.md':continue
        result.append((relative,path.read_bytes()))
    return result


def build(destination):
    destination=destination.resolve()
    if destination.exists():raise ValueError('Choose a new output directory; existing releases are not overwritten')
    destination.mkdir(parents=True)
    source=source_files()
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    report={'schema':'suite-source-release.v1','source_commit':head,'worktree_changes':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).strip()),'components':{}}
    specs=(('authorization-platform',None),('direct-link-site','独立直链站'),('software-showcase','展示网站'))
    for name,prefix in specs:
        members={}
        for relative,raw in source:
            if prefix:
                if relative.parts[0]!=prefix:continue
                local=Path(*relative.parts[1:])
            else:
                if relative.parts[0] in {'独立直链站','展示网站'}:continue
                local=relative
            members[local.as_posix()]=raw
        if 'manage.py' not in members:raise ValueError('Incomplete component '+name)
        manifest={'component':name,'source_commit':head,'files':{p:{'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for p,raw in sorted(members.items())}}
        inventory=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
        archive=destination/(name+'.tar.gz')
        with tarfile.open(archive,'w:gz') as out:
            for local,raw in sorted({**members,'SOURCE-MANIFEST.json':inventory}.items()):
                entry=tarfile.TarInfo(name+'/'+local);entry.size=len(raw);entry.mode=0o644;entry.uid=entry.gid=0;entry.uname=entry.gname='root';entry.mtime=0
                out.addfile(entry,io.BytesIO(raw))
        # Verify the artifact bytes themselves, not just input files.
        with tarfile.open(archive,'r:gz') as incoming:
            for local,raw in members.items():
                if incoming.extractfile(name+'/'+local).read()!=raw:raise ValueError('Archive mismatch')
        report['components'][name]={'file':archive.name,'files':len(members),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
        if prefix=='展示网站':
            zip_path=destination/'展示网站-源码交付.zip'
            with zipfile.ZipFile(zip_path,'x',compression=zipfile.ZIP_DEFLATED) as out:
                for local,raw in sorted({**members,'SOURCE-MANIFEST.json':inventory}.items()):out.writestr('展示网站/'+local,raw)
            with zipfile.ZipFile(zip_path) as check:
                if check.testzip() is not None:raise ValueError('ZIP CRC failure')
                for local,raw in members.items():
                    if check.read('展示网站/'+local)!=raw:raise ValueError('ZIP content mismatch')
            report['showcase_zip']={'file':zip_path.name,'sha256':hashlib.sha256(zip_path.read_bytes()).hexdigest()}
    (destination/'交付清单.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    print(json.dumps(build(parser.parse_args().output),ensure_ascii=False,indent=2))
