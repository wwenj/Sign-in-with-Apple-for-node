const express = require('express')
const app = express()
const path = require('path')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken');
const fs = require('fs')
const axios = require('axios')
const qs = require('qs');
const apple = require('./static/appleAuth');
const NodeRSA = require('node-rsa');

// 生成跳转授权验证页的URL
const getAuthorizationUrl = () => {
	const url = new URL('https://appleid.apple.com/auth/authorize');
	url.searchParams.append('response_type', 'code id_token');
	url.searchParams.append('response_mode', 'form_post');
	url.searchParams.append('state', 'state');
	url.searchParams.append('client_id', apple.client_id);
	url.searchParams.append('redirect_uri', apple.url);
	url.searchParams.append('scope', 'openid');
	return url.toString();
};
//   生成JWT
const getClientSecret = () => {
	const privateKey = fs.readFileSync('./static/AuthKey_XH*****B9S.txt', { encoding: "utf-8" });
	const headers = {
		alg: 'ES256',
		kid: apple.key_id,
	}
	const timeNow = Math.floor(Date.now() / 1000);
	const claims = {
		iss: apple.team_id,
		aud: 'https://appleid.apple.com',
		sub: apple.client_id,
		iat: timeNow,
		exp: timeNow + 15777000,
	}

	token = jwt.sign(claims, privateKey, {
		algorithm: 'ES256',
		header: headers,
		// expiresIn: '24h'
	});
	return token
}

// 获取access token，/appleAuth接口就是当时填写的重定向url
app.post('/appleAuth', bodyParser.urlencoded({ extended: false }), (req, res) => {
	const params = {
		grant_type: 'authorization_code', // refresh_token authorization_code
		code: req.body.code,
		redirect_uri: apple.url,
		client_id: apple.client_id,
		client_secret: getClientSecret(),
		// refresh_token:req.body.id_token
	}
	axios.request({
		method: "POST",
		url: "https://appleid.apple.com/auth/token",
		data: qs.stringify(params),
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		}
	}).then(response => {
		verifyIdToken(response.data.id_token, apple.client_id).then((jwtClaims) => {
			return res.json({
				message: 'success',
				data: response.data,
				verifyData: jwtClaims
			})
		})
	}).catch(error => {
		return res.status(500).json({
			message: '错误',
			error: error.response.data
		})
	})
})
// 验证access token
const getApplePublicKey = async () => {
	let res = await axios.request({
		method: "GET",
		url: "https://appleid.apple.com/auth/keys",
	})
	let key = res.data.keys[0]
	const pubKey = new NodeRSA();
	pubKey.importKey({ n: Buffer.from(key.n, 'base64'), e: Buffer.from(key.e, 'base64') }, 'components-public');
	console.log('apple公钥')
	console.log(pubKey.exportKey(['public']))
	return pubKey.exportKey(['public']);
};
const verifyIdToken = async (idToken, clientID) => {
	console.log(idToken, clientID)
	const applePublicKey = await getApplePublicKey();
	const jwtClaims = jwt.verify(idToken, applePublicKey, { algorithms: 'RS256' });
	console.log(jwtClaims)
	return jwtClaims;
};
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')))
app.listen(process.env.PORT || 80, () => console.log(`App listening on port ${process.env.PORT || 80}!`))
