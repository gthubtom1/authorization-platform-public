---
name: "独立软件展示网站"
description: "已定稿的深蓝顶栏、横向分类与完整软件图文目录；后台保留现有蓝白操作界面。"
colors:
  navy: "#101c39"
  catalog-blue: "#214bd7"
  catalog-blue-hover: "#193cba"
  catalog-ink: "#14213c"
  catalog-body: "#46516a"
  catalog-muted: "#626e83"
  catalog-paper: "#f6f7fa"
  catalog-line: "#dbe0ea"
  surface: "#ffffff"
  stage-start: "#17357a"
  stage-end: "#365fd7"
  blue: "#2144c9"
  blue-deep: "#1736aa"
  ink: "#12254b"
  body: "#435575"
  muted: "#5c6e8d"
  line: "#ccd7e9"
  control: "#8497b5"
  danger: "#a62e36"
  success: "#22664b"
  admin-background: "#f3f6fb"
  admin-selected: "#e1e9fc"
typography:
  catalog-heading:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "clamp(36px, 3.2vw, 52px)"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.03em"
  product-heading:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "clamp(30px, 3vw, 48px)"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.025em"
  description:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.95
  action:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "14px"
    fontWeight: 600
    lineHeight: 1.5
  count:
    fontFamily: 'Catalog, "Segoe UI", "Microsoft YaHei", sans-serif'
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.7
rounded:
  image: "6px"
  control: "8px"
  gallery: "14px"
  dialog: "12px"
  admin-control: "7px"
spacing:
  tight: "8px"
  controls: "12px"
  mobile: "20px"
  desktop: "48px"
  row: "32px"
  wide: "40px"
components:
  catalog-primary:
    backgroundColor: "{colors.catalog-blue}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "12px 22px"
    height: "50px"
  catalog-primary-hover:
    backgroundColor: "{colors.catalog-blue-hover}"
  admin-primary:
    backgroundColor: "{colors.blue}"
    textColor: "{colors.surface}"
    rounded: "{rounded.admin-control}"
    padding: "10px 20px"
    height: "46px"
---

# Design System: 独立软件展示网站

## Overview

负责人2026-11-17确认“定成这样”并授权部署：以已认可的界面预览为视觉依据，正式源为templates/catalog.html、cards.html与static/public-catalog.css。主视觉是深海军蓝顶栏、横向分类、皇家蓝截图承托与冷白阅读面。每行一款软件，完整介绍直接显示；软件图像承担视觉表现，页面不添加虚构商品、评分或营销指标。

管理端属于操作界面，保留static/site.css的现有蓝白设计。本次只将后台“已保存内容预览”同步到新公开图文样式；分类管理、编辑表单和登录不换布局。界面预览目录是确认依据，不是另一套部署入口。

## Colors

公开站使用catalog-*、navy和stage-*色：深蓝页头、白色标题、浅蓝次级字，主操作与页码用catalog-blue。截图承托为125度stage-start至stage-end渐变；真实截图完整显示。表单与图像浮层保持可读对比。管理端继续使用blue、ink、body等旧令牌，禁止从公开站CSS全局覆盖管理端。

## Typography

Catalog为项目自带Noto Sans SC子集，400/500/600/700字重及OFL许可保留；不依赖远程字体。目录标题为36–52px，软件名30–48px，介绍16px/1.95，辅助13px，图片提示12px。数字使用tabular-nums。手机标题32px、软件名32px。介绍不截断、不折叠、不设独立滚动框，长文本自然撑高。

## Layout

内容宽度为视口减96px，最大1728px。页头80px，标题区上下26px，横向分类最少58px，可自然换行。软件行两列比例1.32:1，间距clamp(32px,4vw,76px)，上下32/36px；图片列与说明列拉伸，按钮使用margin-top:auto位于右下角，不绝对定位覆盖文字。

截图底板必须width:100%，比例16:10，高度上限500px；此规则防止宽屏底板缩至672px。截图object-fit:contain，不裁切。图注与底板同宽，图片在长介绍桌面行内sticky top24px。

断点：1100px内左右32px、列比1.12:1；760px内左右20px且图上文下，图片不粘附、按钮等分；520px内搜索独占一行，截图16:11、内边距16px；1800px以上行上下40px、图垫36px。320px可正常阅读，无横向溢出。分类保持正常文档流，不再用固定侧栏或手机抽屉。

分页始终显示总数、当前页与前后页；单页前后页为aria-disabled的不可点击文本。页码包括首尾、当前相邻及必要省略号；搜索和分类随页码保留。页脚正常流、pre-wrap及overflow-wrap，不能因固定高度裁切。

## Elevation & Depth

图文行保持开放，无外层卡片。截图阴影0 14px 30px #152c5530，按钮悬停0 7px 16px #214bd729；不推广到管理列表。大图遮罩#060f24eb，面板#101a2e。图片蓝色承托是展示材料，不承载额外文本。

## Shapes

图片底板14px、截图6px、按钮8px、大图12px。图标用24px内联SVG、1.6px圆端点描边；品牌32px。图内箭头46×48px，手机至少44×46px。图标尺寸不替代按钮触达面积。

## Components

公开主操作最少50px高，下载描边、购卡实底，桌面至少148px宽；手机等分。搜索为真实GET表单，保留当前分类，无JavaScript仍可使用。分类链接带aria-current；选中底线3px。操作名称、实际/go跳转、权限受控/image路径均延用原合同。

多图箭头在图片内，单图不显示；支持滑动、点击大图、左右键、Escape、遮罩关闭；关闭焦点回到当前可见图。切图仅一次280ms clip-path揭示，减少动态效果时停用；默认内容始终可见。缺图显示明确文案，加载失败可刷新重试。公开页面不显示本地预览说明，后台保存预览才提示不执行下载/购买。

管理控件继续按site.css，最少46px高度、7px圆角，危险/成功同时有文字。后台不加载public-catalog.css。

## Do's and Don'ts

- 保留完整介绍、真实图片、右下操作、可见分页和自然页脚。
- 浏览器选择、焦点、滚动条与减少动态效果沿主题设置；减少动态效果不能隐藏内容。
- 页面不堆技术解释、演示说明、无依据的版本/销量/评分。
- 不恢复旧侧栏，不拿旧A/B目录作维护源；不把本地测试商品带入生产。
- 部署只走本站安装器，保留正式内容、账号和数据卷；以公网资源实际字节与浏览器结果验证上线。
