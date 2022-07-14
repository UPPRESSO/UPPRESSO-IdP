简单部署说明：
安装maven工具
将IdP/oauth目录下执行mvn -DskipTests -Dmaven.javadoc.skip=true package install
在IdP目录下执行mvn -DskipTests -Dmaven.javadoc.skip=true clean install
在IdP\openid-connect-server-webapp目录下执行mvn jetty:run-war
可以尝试在intellij idea里操作maven命令

默认的配置为本地的8080端口
