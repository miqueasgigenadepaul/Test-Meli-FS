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
      const params = new URLSearchParams()
      params.append('grant_type', 'authorization_code')
      params.append('client_id', APP_ID)
      params.append('code', code)
      params.append('redirect_uri', REDIRECT_URI)
      params.append('code_verifier', codeVerifier)

    const tokenResponse = await axios.post('https://api.mercadolibre.com/oauth/token', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
})
      accessTokenGlobal = tokenResponse.data.access_token
      refreshTokenGlobal = tokenResponse.data.refresh_token

      console.log('Access Token:', accessTokenGlobal)
      console.log('Refresh Token:', refreshTokenGlobal)

      // Borrar la cookie luego de usarla
      res.clearCookie('code_verifier')

      res.send('✅ Autenticación exitosa. Ya podés usar /api/items?q=...')
    } catch (error) {
      console.error('❌ Error intercambiando código:')
      if (error.response) {
        console.error('🧾 Status:', error.response.status)
        console.error('📦 Data:', error.response.data)
      } else {
        console.error('❗ Error:', error.message)
      }
  res.status(500).send('❌ Error intercambiando el código de autorización.')
}

  } else {
    res.sendFile(path.join(__dirname, 'dist/index.html'))
  }
})

// Función para refrescar el access token usando refresh token
async function refreshAccessToken() {
  if (!refreshTokenGlobal) throw new Error('No hay refresh token disponible')

  try {
    const params = new URLSearchParams()
    params.append('grant_type', 'refresh_token')
    params.append('client_id', APP_ID)
    params.append('refresh_token', refreshTokenGlobal)

    const response = await axios.post('https://api.mercadolibre.com/oauth/token', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })

    accessTokenGlobal = response.data.access_token
    refreshTokenGlobal = response.data.refresh_token

    console.log('Access token renovado:', accessTokenGlobal)
    console.log('Refresh token renovado:', refreshTokenGlobal)

  } catch (error) {
    console.error('Error refrescando token:', error.response?.data || error.message)
    throw error
  }
}


// Endpoint para probar el refresh manualmente
app.get('/refresh', async (req, res) => {
  try {
    await refreshAccessToken()
    res.json({ access_token: accessTokenGlobal, refresh_token: refreshTokenGlobal })
  } catch {
    res.status(500).json({ error: 'No se pudo refrescar el token' })
  }
})

// Endpoint para buscar productos, con manejo automático de refresh token
app.get('/api/items', async (req, res) => {
  const query = req.query.q
  if (!accessTokenGlobal) {
    return res.status(401).json({ error: 'Primero autenticá vía /auth para obtener el token.' })
  }
  if (!query) {
    return res.status(400).json({ error: 'Faltó el parámetro q en la consulta.' })
  }

  try {
    const result = await axios.get('https://api.mercadolibre.com/sites/MLA/search', {
      params: { q: query },
      headers: { Authorization: `Bearer ${accessTokenGlobal}` }
    })
    return res.json(result.data)

  } catch (error) {
    if (error.response?.status === 401) {
      // Token expirado, intentamos refrescarlo
      console.log('Token expirado, intentando refrescar...')
      try {
        await refreshAccessToken()
        // Reintentar la consulta con nuevo token
        const result = await axios.get('https://api.mercadolibre.com/sites/MLA/search', {
          params: { q: query },
          headers: { Authorization: `Bearer ${accessTokenGlobal}` }
        })
        return res.json(result.data)
      } catch (refreshError) {
        console.error('Falló refrescar el token:', refreshError.response?.data || refreshError.message)
        return res.status(401).json({ error: 'No se pudo refrescar el token, volvé a autenticar.' })
      }
    }

    console.error('Error consultando Mercado Libre:', error.response?.data || error.message)
    return res.status(500).json({ error: 'Falló la consulta a Mercado Libre' })
  }
})

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`)
})