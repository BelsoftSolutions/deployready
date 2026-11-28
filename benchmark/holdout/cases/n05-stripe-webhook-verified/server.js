const express = require('express')
const Stripe = require('stripe')
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)
const app = express()

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  let event
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)
  } catch (err) {
    return res.status(400).send('bad signature')
  }
  if (event.type === 'checkout.session.completed') {
    // fulfil order
  }
  res.json({ received: true })
})

app.use(express.json())
app.listen(3000)
