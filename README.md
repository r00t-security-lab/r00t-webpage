# www.r00team.cc 文档编写指南

[![Github Build Status](https://github.com/r00t-security-lab/r00t-webpage/workflows/Build%20and%20Deploy/badge.svg)](https://github.com/r00t-security-lab/r00t-webpage/actions?query=workflow%3A%22Build+and+Deploy%22)

^^^ 如果这里变红了，请及时联系维护者 ^^^

## 文档编写和部署

1. clone项目

```sh
git clone git@github.com:r00t-security-lab/r00t-webpage.git
```

2. 编辑文档

在docs添加文档，各个目录的首页默认页面为`README.md`，记得添加链接索引

3. `git push`。GitHub CI 会自动生成、部署网站，实时更新。

## 在本地预览网站效果（Vuepress）

关于Vuepress的介绍请查看[Vuepress-快速上手](https://vuepress.vuejs.org/zh/guide/getting-started.html)

需要先安装nodejs和yarn。

在本项目目录运行`yarn`拉取依赖，再使用`yarn docs:dev`启动实时更新的本地服务。

