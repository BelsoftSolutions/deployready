import { initializeApp } from 'firebase/app'
import { getAuth } from 'firebase/auth'

// Firebase web config is public by design; access is enforced by security rules.
const app = initializeApp({
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: 'demo-app.firebaseapp.com',
  projectId: 'demo-app',
})
export const auth = getAuth(app)
