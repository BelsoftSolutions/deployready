import { initializeApp } from 'firebase/app'
import { getFirestore, collection, getDocs } from 'firebase/firestore'
const app = initializeApp({ apiKey: 'AIzaSyD-example-public-web-key', projectId: 'demo-chat' })
export const db = getFirestore(app)
export const messages = () => getDocs(collection(db, 'messages'))
