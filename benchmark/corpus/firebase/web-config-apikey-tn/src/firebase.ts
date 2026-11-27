import { initializeApp } from 'firebase/app';

// The web config is public by design: access is enforced by security rules.
export const app = initializeApp({
  apiKey: 'AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q',
  authDomain: 'demo-app.firebaseapp.com',
  projectId: 'demo-app',
  storageBucket: 'demo-app.appspot.com',
  messagingSenderId: '123456789012',
  appId: '1:123456789012:web:abcdef1234567890',
});
