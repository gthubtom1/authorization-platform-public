---
name: "软件展示站预览 · A/B 并列设计系统"
description: "同一软件目录的深色卡片版与明亮发行目录版；两版均为待比较的静态预览。"
colors:
  a-sage: "#c9dbaf"
  a-sage-ink: "#21331b"
  a-sage-hover: "#e0eccc"
  a-selected: "#2b3429"
  a-selected-text: "#e1eed7"
  a-background: "#151719"
  a-sidebar: "#101214"
  a-panel: "#1c1f21"
  a-raised: "#282d2f"
  a-line: "#3a4144"
  a-text: "#f0f1ee"
  a-secondary: "#c1c6c5"
  a-muted: "#a5afaf"
  a-field: "#1b1e20"
  a-hover: "#2c3234"
  a-control-border: "#6c7778"
  a-image-stage: "#12191c"
  b-cobalt: "#2144c9"
  b-cobalt-hover: "#1534ad"
  b-navigation-hover: "#2d51d8"
  b-selected-ink: "#1736aa"
  b-navigation-secondary: "#cdd8ff"
  b-background: "#f8faff"
  b-white: "#fff"
  b-text: "#12254b"
  b-secondary: "#435575"
  b-muted: "#5c6e8d"
  b-line: "#d0dbea"
  b-control-border: "#8ba0c0"
  b-hover: "#e8eefb"
  b-image-mat: "#e0e9fb"
  b-feedback: "#e4ecfc"
  b-feedback-ink: "#243f72"
typography:
  a-headline:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "32px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.03em"
  a-title:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "25px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "-0.025em"
  b-headline:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "44px"
    fontWeight: 700
    lineHeight: 1.15
    letterSpacing: "-0.035em"
  b-title:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "28px"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "-0.03em"
  shared-body:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.7
  shared-description:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.95
  shared-action:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "14px"
    fontWeight: 600
    lineHeight: 1.7
  shared-search:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.7
  shared-status:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.7
  shared-label:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.7
rounded:
  variant-tab: "5px"
  compact-control: "6px"
  action-a: "7px"
  field-a: "8px"
  image-mat-b: "12px"
  product-a: "14px"
spacing:
  tight: "8px"
  control-gap: "12px"
  compact: "16px"
  group: "20px"
  section: "24px"
  row-a: "28px"
  gutter: "32px"
  row-b: "36px"
  desktop-edge: "40px"
  wide-gap: "48px"
components:
  a-button-purchase:
    backgroundColor: "{colors.a-sage}"
    textColor: "{colors.a-sage-ink}"
    typography: "{typography.shared-action}"
    rounded: "{rounded.action-a}"
    padding: "0 20px"
    height: "46px"
  a-button-purchase-hover:
    backgroundColor: "{colors.a-sage-hover}"
  a-button-download:
    backgroundColor: "transparent"
    textColor: "{colors.a-text}"
    typography: "{typography.shared-action}"
    rounded: "{rounded.action-a}"
    padding: "0 20px"
    height: "46px"
  b-button-purchase:
    backgroundColor: "{colors.b-cobalt}"
    textColor: "{colors.b-white}"
    typography: "{typography.shared-action}"
    rounded: "{rounded.compact-control}"
    padding: "0 22px"
    height: "48px"
  b-button-purchase-hover:
    backgroundColor: "{colors.b-cobalt-hover}"
  b-button-download:
    backgroundColor: "transparent"
    textColor: "{colors.b-cobalt}"
    typography: "{typography.shared-action}"
    rounded: "{rounded.compact-control}"
    padding: "0 22px"
    height: "48px"
  a-search:
    backgroundColor: "{colors.a-field}"
    textColor: "{colors.a-text}"
    typography: "{typography.shared-search}"
    rounded: "{rounded.field-a}"
    padding: "2px 14px"
    height: "48px"
    width: "280px"
  b-search:
    backgroundColor: "transparent"
    textColor: "{colors.b-text}"
    typography: "{typography.shared-search}"
    rounded: "{rounded.compact-control}"
    padding: "2px 14px"
    height: "48px"
    width: "280px"
  a-category-selected:
    backgroundColor: "{colors.a-selected}"
    textColor: "{colors.a-selected-text}"
    rounded: "{rounded.field-a}"
    padding: "14px 12px"
    height: "52px"
  b-category-selected:
    backgroundColor: "{colors.b-white}"
    textColor: "{colors.b-selected-ink}"
    rounded: "{rounded.action-a}"
    padding: "14px 12px"
    height: "52px"
  a-product-row:
    backgroundColor: "{colors.a-panel}"
    rounded: "{rounded.product-a}"
    padding: "28px"
  b-product-row:
    backgroundColor: "transparent"
    padding: "36px 0"
---

# Design System: 软件展示站预览

## Overview

**Creative North Star: "软件目录的两种表达"**

这是当前子目录中两个已实现预览的设计记录。A（`index.html`）保留石墨黑、鼠尾草绿与封闭卡片；B（`redesign.html`）采用钴蓝分类侧栏、冷白阅读面与开放的图文行。两者是并列候选，没有被选定的最终版；新增工作必须明确沿用哪个命名空间。

记录以现有 HTML 为依据。两版共用嵌入的中文字体、内容和交互，视觉差异来自空间、字级、容器和图片承托方式。这里不定义上级授权平台的界面；产品事实见本目录 `PRODUCT.md`，本轮页面策略与比较合同见 `.impeccable/surfaces/index-html.md`。

**Key Characteristics:**

- A：安静的深色阅读面，图文封装在独立的细边框卡片内。
- B：完整的钴蓝分类带，开放行、清楚分隔与浅蓝图片底面。
- 同一处完成读介绍、看多图和识别两个操作，正文随内容自然增高。
- 状态反馈留在当前条目；键盘与触屏均可操作。

## Colors

颜色在 frontmatter 中按 `a-` 与 `b-` 分开；名称描述使用位置，不构成已确认的品牌资产。

### Primary

- **A 鼠尾草绿**：购买按钮、焦点、选择文本和品牌几何标记；深绿墨色用于浅绿底上的文字。选中分类使用更深的绿灰底，与购买按钮保持层级差异。
- **B 钴蓝**：侧栏、购买按钮、下载按钮描边、页码选中态与焦点。白色选中分类把当前目录从连续蓝底中提取出来；深蓝承担该选中态的文字。

### Neutral

- **A 石墨层次**：页面、侧栏、产品面、反馈面和图片台分别使用对应的 `a-` 中性色；正文、次级正文和说明有三个明确层级。控件边框比普通分隔线更清楚。
- **B 冷白与海军蓝**：正文面与白色控件配深蓝标题、蓝灰段落和说明。浅蓝图片底面只承托软件截图；行间分隔使用轻线。侧栏次级文字使用浅蓝。
- **反馈**：A 使用略抬高的深灰面；B 使用浅蓝面和深蓝文字，均保留在操作按钮下方。

**The Variant Boundary Rule.** 先选 A 或 B 的命名空间，再应用该版的颜色与容器；不要把两版各取一半当成默认系统。

## Typography

**Display Font:** Catalog，实际为嵌入的 Noto Sans SC 子集；回退为 Segoe UI、Microsoft YaHei、sans-serif。

**Body Font:** 同一字体栈。HTML 内含四个正常字重（400、500、600、700）及 SIL OFL 1.1 许可；此记录不复制字体数据。

**Character:** 中文无衬线字型以清楚阅读为主。A 使用较紧凑的标题，B 用更大的粗标题建立目录感；正文不通过减小字号压缩长介绍。

### Hierarchy

- **A 页面标题**：使用 `a-headline`；手机降至（30px）。产品标题使用 `a-title`；宽屏（≥1600px）为（27px），紧凑桌面（≤1200px）为（23px），抽屉与手机范围（≤900px）为（24px）。
- **B 页面标题**：使用 `b-headline`；紧凑桌面为（40px），手机（≤680px）为（38px）。产品标题使用 `b-title`；宽屏为（30px），紧凑桌面为（26px），手机为（27px）。
- **介绍正文**：两版共用 `shared-description`，最大行长（72ch）；段落间距 A 为（14px），B 为（16px）。
- **操作和搜索**：分别使用 `shared-action` 与 `shared-search`。结果计数、分页说明使用 `shared-status`，分类计数与元信息使用 `shared-label`。
- **数字**：分类数量、图片计数、结果计数和分页状态使用等宽数字（`tabular-nums`），不更换为装饰性等宽字体。

**The Complete Copy Rule.** 软件介绍完整显示，条目由内容决定高度；不使用截断、折叠、展开按钮或独立文字滚动框。

## Layout

桌面使用固定分类侧栏与右侧单列目录。A 侧栏（224px），B（232px）；主区域最大宽度均为（1312px），正常左右内边距（40px）。A 顶栏（72px）、内容顶部（40px）；B 顶栏（76px）、内容顶部（24px）。顶栏不固定。

产品在桌面保持左图右文。A 的列比为（1 : 1.16）、列间（32px），卡内边距使用 `row-a`，条目间距（28px）。B 的列比为（1.02 : 1.15）、列间（40px），使用上下（36px）的开放行和底部分隔线，行间无额外 gap。图片区域在较长介绍旁保持粘附（距视口顶部24px）。

两版图片保持完整显示（`object-fit: contain`），不裁切软件界面。A 图片区比例（16:10）；B 截图承托面比例（16:11），内边距（24px），真正截图在内层。图片计数与前后切换按钮在图片下方，不覆盖软件界面。

### Responsive behavior

| 范围 | 两版共同变化 | A | B |
| --- | --- | --- | --- |
| ≥1600px | 加大产品内部空间 | 卡内32px，列间40px | 行上下44px，列间48px |
| ≤1200px | 主区横向28px；搜索250px；隐藏面包屑 | 侧栏200px，卡内24px，列比0.95:1.1 | 侧栏208px，行上下32px，列比1:1.12，图片垫20px |
| ≤900px | 分类改抽屉；主区不再留侧栏；顶栏68px；主区横向24px | 抽屉260px | 抽屉272px，顶栏白底 |
| ≤680px | 标题与搜索上下排；搜索铺满；图在文上；图片不粘附；两操作等分；分页与页脚上下排；主区横向16px | 卡内18px，条目间24px | 开放行上下28px，图片垫20px |
| ≤359px | 比较切换与少量控件缩紧 | 卡内14px，操作文字13px | 继承紧凑控件规则，仍保留开放行 |

这些断点是当前实现，不是另一套按设备名称推导的断点。按钮的 `height` token 记录基准最小高度；实际内容可增高。移动端两个主要操作均至少（48px）高。

## Elevation & Depth

A 的主要结构由色面与细线形成，没有卡片阴影。B 的目录行保持平面，只有放在浅蓝承托面上的截图有柔和下落阴影（`0 12px 24px #00000026`），用来区分界面图片与站点背景。不要把这层截图阴影扩展到每个控件。

原生大图对话框使用遮罩分离当前查看任务；A 遮罩（`#080d13e8`），B（`#10224be8`）。手机分类抽屉共用遮罩（`#060d17b8`），抽屉本身不加阴影。

**The Image Lift Rule.** B 的柔和抬升只属于截图；A 的产品卡与 B 的目录行按各自的平面结构延续。

## Shapes

A 产品卡与大图对话框使用柔和圆角 `product-a`；A 图片、搜索框和分类项使用 `field-a`。B 的目录行没有外框和圆角，图片承托面使用 `image-mat-b`，图片内层与主要操作使用 `compact-control`。大图对话框在 B 中仍保留共享的（14px）圆角，不按目录行的零圆角处理。

普通控件与卡片用（1px）边线。图片前后、关闭大图和回到顶部的触达尺寸为（44×44px）；图标尺寸不等于点击区域。图标是同一套内联 SVG：画布（24×24）、线宽（1.6）、圆端点与圆转角。常规图标（20px），分类/搜索（18px），操作/图片箭头（17px），放大指示（16px）。品牌标记是单独的四格几何图（28×28、线宽1.5），不使用字符图标。

## Components

### Buttons

下载与购买始终是独立操作。A 下载为描边、购买为浅绿实色；B 下载为蓝描边、购买为蓝色实底。桌面最小宽度（136px）；移动端去掉最小宽度、等分行宽、横向内边距（12px）。

悬停通过底色/描边变化反馈，不位移。普通按钮的颜色过渡（180ms），缓动（`cubic-bezier(.16,1,.3,1)`）。禁用按钮不透明度（0.38）、默认光标；分页到首尾时正确禁用。所有按钮与链接有（2px）可见焦点、外偏移（4px）；B 蓝色侧栏内改用白色焦点。

### Inputs / Fields

搜索框使用内联搜索图标、真实隐藏标签和单行搜索输入。输入最小高度（42px），外框至少（48px）；有内容时出现清空按钮。A 使用深色输入面，B 桌面透明、手机白底。聚焦整组外框（2px）且外偏移（3px），避免同时给输入再画一圈。光标使用本版主色。

搜索覆盖全部软件的名称、功能标签与完整介绍；搜索时标题切为“搜索结果”，分类不假装仍被选中。空结果保留明确提示与“查看全部软件”恢复操作。当前数据本地同步读取，不记录不存在的网络加载、服务器成功或失败样式。

### Navigation

分类项至少（52px）高，图标、名称、数量组成稳定横排；长分类名可换行。选中项同时有视觉状态与 `aria-current`。A 使用深绿灰选中面，B 使用白色选中面。数量表示完整示例目录中的分类数量，不随当前分页减少。

手机抽屉打开后锁定页面滚动、把后方内容设为 inert，并约束 Tab/Shift+Tab；Escape、遮罩和关闭按钮均可退出，关闭后恢复触发按钮焦点。抽屉关闭时不可键盘进入。

A/B 比较入口保留当前分类、页码与关键词；浏览器前进/后退恢复目录筛选。每页（8）款软件，只有多页时显示分页导航，换分类或分页后将焦点带到目录标题。

### Product rows and galleries

A 的卡片外框与 B 的开放行都容纳图片、标题、分类/功能元信息、全部介绍、两按钮和当前操作反馈。元信息的小圆点仅为文本分隔，不承担图标语义。

多图使用下方两个（44×44px）按钮并循环切换，计数以 polite live region 更新；触屏可横向滑动。单图不显示前后切换按钮。点击图片打开原生 `dialog` 大图，支持 Escape、遮罩退出和左右键；关闭后焦点回到图片入口。大图中的单图导航同时隐藏并禁用。

### Feedback and browser surfaces

目前下载/购买未配置真实地址，点击后在当前条目按钮下显示对应预览说明（`role=status`、`aria-live=polite`），可关闭；关闭时回到下载按钮。它不是下载成功提示，也不打开无关确认弹窗。

文本选择使用当前主色与主色墨色；滚动条与光标随主题着色；链接下划线偏移（4px）。超过滚动位置（600px）后出现回顶按钮。减少动态效果偏好下禁用过渡，回顶使用即时滚动；默认无页面入场动画。

## Do's and Don'ts

### Do:

- **Do** 保留 A/B 两个独立命名空间，并以相同示例数据与功能继续比较。
- **Do** 保持桌面左图右文、手机图文上下排列，完整介绍自然撑高条目。
- **Do** 把图片切换控件放在截图下方，保留44px触达区和清楚的图片计数。
- **Do** 延续真实标签、可见焦点、抽屉焦点约束及大图关闭后的焦点恢复。
- **Do** 保留软件、界面图片和链接的示例标记；嵌入字体继续附带现有OFL许可。

### Don't:

- **Don't** 把 B 记成胜出方案，或把当前字体、品牌文字和配色说成用户已确定的正式品牌。
- **Don't** 截断、折叠软件介绍，增加详情页，或把正文放进独立滚动框。
- **Don't** 把示例操作反馈写成真实下载、购买、后台或授权软件接入已经完成。
- **Don't** 将本目录的颜色、圆角或组件规则写回上级授权平台的设计系统。
- **Don't** 将QA截图作为发布素材，或把几何软件界面示意当作真实商品截图。

未固化为规范的缺陷/漂移：本次未发现需固化的额外样式；初审提出的单图大图导航问题已在源码中隐藏并禁用对应控件，本文件只记录修正后的行为。独立终审结论另由交付会话记录，本文件不把源码核对冒充全部浏览器验收。
