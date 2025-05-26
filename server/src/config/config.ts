export default () => ({
  MONGODB_URI:
    process.env.MONGODB_URI ||
    'mongodb+srv://omer:omer@cluster.nolm1.mongodb.net/advance-nest',
  jwt: {
    secret: process.env.JWT_SECRET || 'omer123',
  },
  email: {
    user: process.env.EMAIL_USER || 'syedomerali2006@gmail.com',
    pass: process.env.EMAIL_PASS || 'kxpnffcyrezabekc',
    from: process.env.EMAIL_FROM || 'Syed Omer Ali <syedomerali2006@gmail.com>',
  },
  backendUrl: process.env.BACKEND_URL || 'http://localhost:5000',
  twilio: {
    number: process.env.TWILIO_NUMBER || '+18597128786',
    sid: process.env.TWILIO_SID || 'AC824e7fe9bc1f5ad075290e95a3a88230',
    token: process.env.TWILIO_TOKEN || '47874dfc422795ca0b504458bd882194',
  },
});
