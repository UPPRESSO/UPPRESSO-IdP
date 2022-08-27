#UPRESSO-IdP

##Build

Install maven tools or you can run the following commands within IntelliJ IDEA.

First go to `./spring-security-oauth` and run.

```shell
mvn -DskipTests -Dmaven.javadoc.skip=true package install
```

Next go to `./` and run

```shell
mvn -DskipTests -Dmaven.javadoc.skip=true clean install
```

##Quickstart

go to `./openid-connect-server-webapp` and run

```shell
mvn jetty:run-war
```

then check `localhost:8080`
