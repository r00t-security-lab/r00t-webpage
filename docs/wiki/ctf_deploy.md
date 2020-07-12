---
sidebar: auto
---

# CTF 题目容器部署指南

## web类

**所有web题均需要部署docker**

1. 根据题目需要从[ctfhub](https://hub.docker.com/u/ctfhub)，拉取不同的镜像。本文以
ctfhub/base_web_nginx_php_74为例，Nginx+php7.4，其他的镜像的操作在文档中都有说明。

2. 创建题目文件夹，本文为`web1`

3. 编写`docker-compose.yml`文件

```yml
version: "2"
services:
  web:
    build: .
    image: web1
    ports:
      - "8080:80"
    restart: always
    environment:
      - FLAG=r00t{c604a883-8211-46ef-87a5-94b3ca74f489}
```

其中image为题目名称。ports为`外部端口:内部端口`，外部端口根据需要修改，内部端口统一为80。environment中的FLAG根据需要修改。

4. 编写`Dockerfile`文件

```Dockerfile
FROM ctfhub/base_web_nginx_php_74

COPY flag.sh /flag.sh
COPY src /var/www/html
```

其中第一行FROM的镜像名称为最开始在ctfhub中找到的名称，COPY是将当前目录的文件复制到docker镜像中，根据需要编写

web目录统一在`/var/www/html`

5. 创建flag.sh，题目初始化脚本，根据需要修改

```sh
#!/bin/sh

echo $FLAG > /flag # 将flag写入根目录

export FLAG=not_flag
FLAG=not_flag

rm -f /flag.sh
```

有文件上传或者代码执行的题目，一定要做好权限控制，防止题目被破坏。

6. 创建src文件夹，将题目web目录复制进去

7. 在web1目录中，`docker-compose up -d` 启动

使用`docker-compose stop` 暂停运行
使用`docker-compose down` 删除容器，用于环境重建
使用`docker-compose build` 重新运行Dockerfile

目录结构

```
web1
├── docker-compose.yml
├── Dockerfile
├── flag.sh
└── src
    └── index.php
```

::: tip 注意事项
1. 尽量不要出带有爆破，猜测的题目，避免比赛选手使用爆破工具给服务器带来较大压力
2. 控制解题流程，避免非预期
3. 带有文件上传或者代码执行的题目控制好权限，避免环境被破坏，注意：默认情况下www-data账户可以向web目录写入文件，可以使用`chown`变更web目录权限，权限初始化在flag.sh中操作
:::
