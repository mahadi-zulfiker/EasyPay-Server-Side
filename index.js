require("dotenv").config();
const express = require("express");
const cors = require("cors");
const port = process.env.PORT || 5000;
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();

const corsOptions = {
  origin: ["http://localhost:5173", "http://localhost:5174"],
  optionSuccessStatus: 200,
  credentials:true
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.7uejvxv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    const usersCollection = client.db("MFS").collection("users");
    const transitionCollection = client.db("MFS").collection("allTransition");
    // await client.connect();
    // jwt
    app.post('/jwt',async(req,res)=>{
      const user = req.body;
      console.log('user token',user);
      const token = jwt.sign(user,process.env.ACCESS_TOKEN_SECREAT,{expiresIn:'30d'})
      res
      .cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production' ? true : false , 
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      
      })
      .send({success:true})
    })

    app.post('/logout',async(req,res)=>{
      const user = req.body
      res.clearCookie('token',{
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production' ? true : false ,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        maxAge:0
      }).send({success:true})
    })

    // middleware
    const logger = (req,res,next)=>{

    }

    const verifyToken =(req,res,next)=>{
      const token = req.cookies.token
      if(!token){
        return res.status(401).send({message:'Unauthorize Access'})
      }
      jwt.verify(token,process.env.ACCESS_TOKEN_SECREAT,(error,decoded)=>{
        if(error){
          return res.status(401).send({message:"Unauthorize Access"})
        }
        req.user = decoded
        next()
      })
    }



    // User insart
    app.post("/user", async (req, res) => {
      const user = req.body;
      console.log(user);
      const email = user.email;
      const phone = user.phoneNumber;
      const pin = user.pin;
      const isExist = await usersCollection.findOne({ email });
      if (isExist) {
        return res.send({ message: "User Already Exist" });
      }

      const hasedPin = await bcrypt.hashSync(pin, 14);
      const result = await usersCollection.insertOne({
        ...user,
        pin: hasedPin,
      });
      res.send(result);
    });

    app.post("/login", async (req, res) => {
      const userCredential = req.body;
      console.log(userCredential);
      const email = userCredential.email;
      const pin = userCredential.pin;
      const currentUser = await usersCollection.findOne({ email });
      if (!currentUser) {
        return res.send({ message: "This email is not Exist" });
      }
      const isValiedPin = await bcrypt.compare(pin, currentUser.pin);
      console.log(isValiedPin);
      if (!isValiedPin) {
        return res.status(401).send({ message: "Pin is Incorrect" });
      }
      if (isValiedPin === true) {
        return res.send({ message: "login successful" }).status(200);
      }
    });

    // send mony api
    app.post("/sendmoney", async (req, res) => {
      const sendMoneyData = req.body;
      const senderEmail = sendMoneyData.senderEmail;
      const pin = sendMoneyData.pin;
      const amount = sendMoneyData.amount;
      const receiverphone = sendMoneyData.receiverphone;
      console.log(sendMoneyData);
      const sender = await usersCollection.findOne({ email:senderEmail });
      const receiver = await usersCollection.findOne({phoneNumber:receiverphone})
    if(sender.phoneNumber == receiverphone){
      return res.send({message:"You can't send money yourself"})
    }
      if (!sender) {
        return res.status(401).send({ message: "Sender not Exist" });
      }
      if (sender) {
        const isValiedPin = await bcrypt.compare(pin, sender.pin);
        console.log(isValiedPin);
        if (!isValiedPin) {
          return res.status(401).send({ message: "Pin is Incorrect" });
        }
        if (isValiedPin === true && receiver) {
          const addMoney = {
            $inc:{totalAmount:amount}
          }
          const removeMoney = {
            $inc:{totalAmount:-(amount+(amount*0.05))}
          }
          const result = await usersCollection.updateOne({phoneNumber:receiverphone},addMoney)
          const result2 = await usersCollection.updateOne({email:senderEmail},removeMoney)
          const result3 = await transitionCollection.insertOne({...sendMoneyData,receiverName:receiver.name})
          return res.send({ message: "Send Money Successful",result2,result }).status(200);
        }
      }
    });

    // Cash In api
    app.post('/cashin',async(req,res)=>{
      const cashInData = req.body;
      console.log(cashInData);
      const agentNumber = cashInData.agentNumber;
      const senderEmail = cashInData.senderEmail;
      const amount = cashInData.amount;
      const requestDate = cashInData.date;
      const pin = cashInData.pin;
      const isExistAgent = await usersCollection.findOne({phoneNumber:agentNumber})
      const isExistSender = await usersCollection.findOne({email:senderEmail})
      console.log(isExistAgent,'isExistAgent');
      console.log(isExistSender,'isExistSender');
      if(!isExistAgent){
        return res.status(401).send({message:'Agent Not Founded'})
      }
      if(isExistAgent?.role ==='agent' && isExistSender){
        const isValiedPin = await bcrypt.compare(pin, isExistSender.pin);
        if(!isValiedPin){
          return res.status(401).send({ message: "Pin is Incorrect" });
        }
        if(isValiedPin){
          const newCashInRequest = {
            requestId: new ObjectId(),
            requestNumber: isExistSender.phoneNumber,
            requestAmount: amount,
            requesterName: isExistSender.name,
            requestDate: requestDate
          }
          const updateDocument = {
            $push: { cashInRequest: newCashInRequest }
          };
          const result = await usersCollection.updateOne({phoneNumber:agentNumber},updateDocument)
          
          res.status(200).send({message:'Cash In Request Successful',result})
        }
      }
    })

    // Cash In Request api for agent
    app.get('/cashinrequest/:email',async(req,res)=>{
      const email = req.params.email;
      const isExistEmail = await usersCollection.findOne({email})
      if(!isExistEmail){
        return res.send({message:'Unauthorize'})
      }
      if(isExistEmail.role === 'agent'){
        res.send(isExistEmail?.cashInRequest)
      }
    })

    // cash In approved api for agent
    app.patch('/cashinapproved/:email',async(req,res)=>{
      const email = req.params.email;
      const receiverData = req.body;
      const receiverNumber = receiverData.number;
      console.log(receiverNumber);
      const amount = parseFloat(receiverData.amount);
      const id = receiverData.id
      console.log(email,receiverData);
      const isExist = await usersCollection.findOne({email})
      if(!isExist){
        return res.send({message:'unauthorize'})
      }
      if(isExist.role === 'agent'){
        const receiver = await usersCollection.findOne({phoneNumber:receiverNumber})
        if(!receiver){
          return res.send({message:"Receiver Number Not Founded"})
        }
        
        const updateDoc = {
          $inc:{totalAmount:amount}
        }

        const updateDocument = {
          $inc:{totalAmount:-amount},
          $pull: { cashInRequest: { requestId: new ObjectId(id) } }
        };

        const result = await usersCollection.updateOne({email},updateDocument)
        const result2 = await usersCollection.updateOne({phoneNumber:receiverNumber},updateDoc)
        const result3  = await transitionCollection.insertOne()
        res.send({message:"Cash IN Successful"})
      }
    })

    // Cash Out Api
    app.post('/cashout',async(req,res)=>{
      const cashOutData = req.body;
      const senderEmail = cashOutData.senderEmail;
      const agentNumber = cashOutData.agentNumber;
      const amount = cashOutData.amount;
      const pin = cashOutData.pin;
      const cashOutDate = cashOutData.date;
      const isExistAgent = await usersCollection.findOne({phoneNumber:agentNumber})
      const isExistSender = await usersCollection.findOne({email:senderEmail})
      if(!isExistAgent){
        return res.status(401).send({message:'Agent Not Founded'})
      }
      if(isExistAgent?.role ==='agent' && isExistSender){
        const feeRate = 0.015; 
        const fee = amount * feeRate;
        if(isExistSender.totalAmount<amount+fee){
          return res.status(403).send({message:'Insufficient balance for the transaction and fee.'})
        }
        const addMoney = {
          $inc:{totalAmount:amount+fee}
        }
        const removeMoney = {
          $inc:{totalAmount:-(amount+fee)}
        }
        const addMoneyFromAgent = await usersCollection.updateOne({phoneNumber:agentNumber},addMoney)
        const removeMoneyFromUser = await usersCollection.updateOne({email:senderEmail},removeMoney)
        const result = await transitionCollection.insertOne({...cashOutData,receiverName:isExistSender.name,agentName:isExistAgent.name})
        return res.status(200).send({message:"Cash Out Successful"})
      }
    })

    //Get payment history 
    app.get('/payment/:email',async(req,res)=>{
      const email = req.params.email;
      const result = await transitionCollection.find({senderEmail:email}).toArray()
      res.send(result)
    })

    // Get Role Request for Admin
    app.get('/request/:email',async(req,res)=>{
      const email = req.params.email;
      console.log(email);
      const admin = await usersCollection.findOne({email})
      if(!admin){
        return res.send({message:"Email Not Founded"})
      }
      if(admin){
       const isAdmin = admin.role === 'Admin'
       if(!isAdmin){
        return res.send({message:'unauthorized'})
       }
       if(isAdmin){
        const result = await usersCollection.find({roleRequest:true}).toArray()
        return res.send(result)
       }
      }
    })

    // is valid user
    app.get('/validuser/:email',async(req,res)=>{
      const email = req.params.email;
      const cookie = req.cookies
      console.log(req.cookies,'cookies');
      const isExist = await usersCollection.findOne({email})
      if(isExist){
        res.send(true)
      }
      else{
        res.send(false,'hello')
      }
    })

    // Accept request
    app.put('/accept/:id',async(req,res)=>{
      const role = req.body.requstedRole
      const id = req.params.id;
      console.log(role,id);
      if(role==='user'){
        const updateDoc = {
          $unset: { requstedRole: "",
                    roleRequest :"",
           },
          $set: { role ,totalAmount:10} // Set 'role' field to 'user'
      }
      const result = await usersCollection.updateOne({_id:new ObjectId(id)},updateDoc) 
      return res.send({message:`${role} Role Request Accepted <br/> You Get 10 Tk Welcome Bonus`})
    }
    if(role === 'agent'){
      const updateDoc = {
        $unset: { requstedRole: "",
          roleRequest :"",
        },
        $set: { role ,totalAmount:10000} // Set 'role' field to 'user'
      }
      const result = await usersCollection.updateOne({_id:new ObjectId(id)},updateDoc) 
      return res.send({message:`${role} Role Request Accepted <br/> You Get 10000 Tk Welcome Bonus`})
      }
    })


    // Get User Info as user as agent as Admin
    app.get('/info/:email', verifyToken,async(req,res)=>{
      const email = req.params.email;
      console.log(req.user,'token owner');
      if(email !== req.user.email){
        return res.status(403).send({message:"Forbidden Access"})
      }
      // console.log(cookie);
      const isExist = await usersCollection.findOne({email})
      if(!isExist){
        return res.send({message:"unauthorize"})
      }
      if(isExist){
      res.send(isExist)
      }
    })

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.use("/", (req, res) => {
  res.send("server is running");
});
app.listen(port, () => {
  console.log(`server is running on ${port}`);
});