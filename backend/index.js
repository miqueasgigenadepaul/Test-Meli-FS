require('dotenv').config()
const express = require('express')
const axios = require('axios')
const path = require('path')
const crypto = require('crypto')
const cookieParser = require('cookie-parser') // ✅ nuevo

const app = express()
app.use(express.static('dist'))
app.use(cookieParser()) // ✅ nuevo

let accessTokenGlobal = null
let refreshTokenGlobal = null

const APP_ID = process.env.APP_ID
const REDIRECT_URI = process.env.REDIRECT_URI
const PORT = process.env.PORT || 3001

function generateCodeVerifier() {
  return base64URLEncode(crypto.randomBytes(32))
}

function base64URLEncode(buffer) {
  return buffer.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest()
}

function generateCodeChallenge(codeVerifier) {
  return base64URLEncode(sha256(codeVerifier))
}

// 🔐 Paso 1: Redirigir a Mercado Libre y guardar el code_verifier en una cookie segura
app.get('/auth', (req, res) => {
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = generateCodeChallenge(codeVerifier)

  // Guardar en cookie segura
  res.cookie('code_verifier', codeVerifier, {
    httpOnly: true,
    secure: true, // Requiere HTTPS, perfecto para Render
    maxAge: 5 * 60 * 1000 // 5 minutos
  })

  const authUrl = `https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=${APP_ID}&redirect_uri=${REDIRECT_URI}&code_challenge=${codeChallenge}&code_challenge_method=S256`
  console.log('Redirigiendo a:', authUrl)
  res.redirect(authUrl)
})

// 🔄 Paso 2: Intercambiar el código por el token, leyendo la cookie
app.get('/', async (req, res) => {
  const { code } = req.query
  const codeVerifier = req.cookies.code_verifier // 👈 leer de cookie

  if (code) {
    if (!codeVerifier) {
      return res.status(400).send('No se encontró code_verifier (cookie ausente o expirada).')
    }

    try {
      const tokenResponse = await axios.post('https://api.mercadolibre.com/oauth/token', null, {
        params: {
          grant_type: 'authorization_code',
          client_id: APP_ID,
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: codeVerifier
        },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      })

      accessTokenGlobal = tokenResponse.data.access_token
      refreshTokenGlobal = tokenResponse.data.refresh_token

      console.log('Access Token:', accessTokenGlobal)
      console.log('Refresh Token:', refreshTokenGlobal)

      // Borrar la cookie luego de usarla
      res.clearCookie('code_verifier')

      res.send('✅ Autenticación exitosa. Ya podés usar /api/items?q=...')
    } catch (error) {
      console.error('Error intercambiando código:', error.response?.data || error.message)
      res.status(500).send('❌ Error intercambiando el código de autorización.')
    }
  } else {
    res.sendFile(path.join(__dirname, 'dist/index.html'))
  }
})

// (El resto de tu código sigue igual)
