let p = "18111848663142005571178770624881214696591339256823507023544605891411707081617152319519180201250440615163700426054396403795303435564101919053459832890139496933938670005799610981765220283775567361483662648340339405220348871308593627647076689407931875483406244310337925809427432681864623551598136302441690546585427193224254314088256212718983105131138772434658820375111735710449331518776858786793875865418124429269409118756812841019074631004956409706877081612616347900606555802111224022921017725537417047242635829949739109274666495826205002104010355456981211025738812433088757102520562459649777989718122219159982614304359";
let q = "19689526866605154788513693571065914024068069442724893395618704484701"
let g = "3"
let IdPOrigin = "http://127.0.0.1:8080/openid-connect-server-webapp"
let Cert,  ID_RP,  PID_RP, redirect_uri, payload
let scope;
let t_num;
let name_RP;
let pKey = KEYUTIL.getKey( "-----BEGIN PUBLIC KEY-----\n"+
                           "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n"+
                           "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n"+
                           "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n"+
                           "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n"+
                           "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n"+
                           "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n"+
                           "mwIDAQAB\n"+
                           "-----END PUBLIC KEY-----");


function onReceiveAuthResponse(xmlhttp){
	if (xmlhttp.readyState==4 && xmlhttp.status==200)
        {
            let response = xmlhttp.responseText
            if (response.includes("html")){
            	document.getElementById("login").style = ""
            } else {
            	let postMessageToken = {"Type": "token", "Token": response}
				window.opener.postMessage(JSON.stringify(postMessageToken), redirect_uri);
            }
        }
}


function consent(){
	document.getElementById("user_consent").innerHTML =""
	let xmlhttp = initXML()
	xmlhttp.onreadystatechange = function () {
		onReceiveAuthResponse(xmlhttp)
	}
	let url = IdPOrigin + '/authorize?client_id=' + PID_RP + '&redirect_uri=' + redirect_uri + '&response_type=token&scope=' + scope
	xmlhttp.open("Get", url, true);
	xmlhttp.send();
}

function doAuthorize() {
	document.getElementById("RP_info").innerHTML = "to continue to " + name_RP
	document.getElementById("user_attributes").innerHTML = scope.replace("%20", "<br>")
}


function logFuc(){
	let username = document.getElementById("username").value;
	let password = document.getElementById("password").value;
	let _csrf = document.getElementById("_csrf").value;
	let url = IdPOrigin + "/login"
	let xmlhttp = initXML()
	xmlhttp.onreadystatechange = function () {
		if (xmlhttp.readyState == 3 && xmlhttp.status == 200) {
			let redirection = xmlhttp.responseURL
			if (redirection.endsWith("failure")){

			}else {
				consent()
			}
		} else {

		}
	}
	let body = "username=" + username + "&password=" + password + "&_csrf="+ _csrf + "&submit=Login"
	xmlhttp.open("POST", url, true);
	xmlhttp.setRequestHeader("Upgrade-Insecure-Requests", "1")
	xmlhttp.setRequestHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	xmlhttp.setRequestHeader("Cache-Control", "max-age=0")
	xmlhttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	xmlhttp.send(body);
}



function generateModPow(x, y, z){
	let xbn = nbi();
	let ybn = nbi();
	let zbn = nbi();
	xbn.fromString(x);
	ybn.fromString(y);
	zbn.fromString(z);
	return xbn.modPow(ybn, zbn).toString();
}

function initXML(){
	if (window.XMLHttpRequest)
	{
		//  IE7+, Firefox, Chrome, Opera, Safari 浏览器执行代码
		return new XMLHttpRequest();
	}
	else
	{
		// IE6, IE5 浏览器执行代码
		return ActiveXObject("Microsoft.XMLHTTP");
	}
}

function decodeJWT(data){
	let isValid = KJUR.jws.JWS.verify(data, pKey, ['RS256']);
	if (!isValid)
    	return;
	let parts = data.split('\.')
	let header = parts[0]
	let payload = parts[1]
	let sig = parts[2]
	return {"header": header, "payload": JSON.parse(atob(payload))};
}



function onReceiveCert_RP(data){
	JWTCert = data.Cert
	if (JWTCert==null)
		return;
	let decodedCert_RP = decodeJWT(JWTCert)
	if (decodedCert_RP==null)
		return;
	let ID_RP = decodedCert_RP.payload.ID_RP;
	redirect_uri = decodedCert_RP.payload.redirect_uri;
	name_RP = decodedCert_RP.payload.name_RP;
	PID_RP = generateModPow(ID_RP, t_num, p);
	scope = data.scope
	doAuthorize(PID_RP, redirect_uri, scope);
}




function onReceiveMessage(event){
	const message = JSON.parse(event.data)
	let messageType = message.Type
	switch (messageType) {
		case "Cert":
			onReceiveCert_RP(message);
			break
	}
}
function startSSO(){
	window.addEventListener('message', onReceiveMessage);
	t_num = bigInt.randBetween("0", q).toString();
	let Ready = {'Type':'start', 't': t_num}
	window.opener.postMessage(JSON.stringify(Ready), '*');
}



startSSO();













