<%--
  Created by IntelliJ IDEA.
  User: hms
  Date: 2020/6/14
  Time: 1:13 下午
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<o:header title="Log In" />
<script type="text/javascript" src="resources/js/RSA.js"></script>

<script type="text/javascript" src="resources/js/IdP.js"></script>

<script type="text/javascript">
    <!--

    $(document).ready(function() {
        // select the appropriate field based on context
        $('#<c:out value="${ login_hint != null ? 'j_password' : 'j_username' }" />').focus();
    });

    //-->
</script>
<o:topbar />





<div id="user_consent" >
    <h3>Sign in</h3>
    <div id="RP_info">
        to continue to RP
    </div>
    The following attributes would be offered
    <div id="user_attributes">
        email <br>
        phone number
    </div>
    <input type="submit" class="btn_consent" value="Next" name="submit_consent" onclick="consent()">
</div>















<div class="container-fluid main" id="login" style="display :none ;">

    <h1><spring:message code="login.login_with_username_and_password"/></h1>

    <c:if test="${ param.error != null }">
        <div class="alert alert-error"><spring:message code="login.error"/></div>
    </c:if>


    <div class="row-fluid" >
        <div class="span6 offset1 well">
<%--            <form action="${ config.issuer }${ config.issuer.endsWith('/') ? '' : '/' }login" method="POST">--%>
                <div>
                    <div class="input-prepend input-block-level">
                        <span class="add-on"><i class="icon-user"></i></span>
                        <input id="username" type="text" placeholder="<spring:message code="login.username"/>" autocorrect="off" autocapitalize="off" autocomplete="off" spellcheck="false" value="<c:out value="${ login_hint }" />" id="j_username" name="username">
                    </div>
                </div>
                <div>
                    <div class="input-prepend input-block-level">
                        <span class="add-on"><i class="icon-lock"></i></span>
                        <input id="password" type="password" placeholder="<spring:message code="login.password"/>" autocorrect="off" autocapitalize="off" autocomplete="off" spellcheck="false" id="j_password" name="password">
                    </div>
                </div>
                <div>
                    <input id = "_csrf" type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                    <input type="submit" class="btn" value="<spring:message code="login.login-button"/>" name="submit" onclick="logFuc()">
                </div>
<%--            </form>--%>
        </div>
    </div>
</div>

<o:footer/>

