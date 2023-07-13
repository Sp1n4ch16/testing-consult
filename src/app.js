const express = require("express");
const session = require("express-session");
const app = express();
const flash = require("connect-flash");
const path = require("path");
const nodemailer = require("nodemailer");
const nodemon = require("nodemon");
const { error, assert } = require("console");
const sgMail = require("@sendgrid/mail");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookie = require("cookie-parser");
const cookieparser = require("cookie-parser");
const crypto = require("crypto");
const dotenv = require("dotenv");
const { addListener, send } = require("process");
const fs = require("fs");
const moment = require("moment");
const multer = require("multer");
const paypal = require("paypal-rest-sdk");
const axios = require("axios");
const {
  Register,
  Appointment,
  OnlineConsult,
  Doctor,
  appointmentDone,
  consultDone,
  doctorInfo,
  ScreenRecord,
} = require("./mongodb");
const { Socket } = require("socket.io");
const https = require("https");
const { v4: uuidv4 } = require("uuid");
const MongoClient = require("mongodb").MongoClient;
const sslServer = https.createServer(
  {
    key: fs.readFileSync(path.join(__dirname, "cert", "key.pem")),
    cert: fs.readFileSync(path.join(__dirname, "cert", "cert.pem")),
  },
  app
);
const io = require("socket.io")(sslServer, { cors: { origin: "*" } });

require("dotenv").config();
const templatePath = path.join(__dirname, "../templates");

const createToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET);
};

const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
});

paypal.configure({
  mode: "live", //sandbox or live
  client_id:
    "AYqdpvOQdeWvgTK9bl-cxL7CiF-FcIOdyHgLJfEIG6-FBhvdtTntKlXP_f4u-ZCsiKbxZpwyTGIRvDe6",
  client_secret:
    "EFI2B7zQ5HDBO_nNEe3hjwGeytc7LtGXNpzrpxCATSj93Gw5jDKvIhyMRshsXltx4LYC2Q5hndU8s3L_",
});

const uploadprescription = multer({ dest: "uploads/" }); // Destination folder to temporarily store the uploaded image
//verify the email
const uploadrecord = multer({ dest: "uploads/" });

const verifyEmail = async (req, res, next) => {
  try {
    const user = await Register.findOne({ email: req.body.email });
    const userAdmin = await Doctor.findOne({ email: req.body.email });
    if (user.isVerified) {
      next();
    } else {
      res.redirect("verify");
      console.log("Please Check your email to Verify");
    }
  } catch (err) {
    res.redirect("loginFailed");
    console.log(err);
  }
};

//nodemailer sender details
var transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

//socket.io chat
const users = {};

io.on("connection", socket => {
  socket.on("join-room", (roomId, userId, user) => {
    socket.join(roomId);
    socket.broadcast.emit("connected", userId);
    //socket.broadcast.emit("user-connected", userId);
    console.log("Your rommId is " + roomId);

    socket.on("disconnect", () => {
      socket.broadcast.emit("user-disconnected", users[socket.id]);
      //socket.to(roomId).emit('user-disconnected', userId)
      delete users[socket.id];
    });
  });
  socket.on("join", name => {
    users[socket.id] = name;
    console.log(name);
    socket.broadcast.emit("user-connected", name);
  });
  socket.on("join-email", email => {
    users[socket.id] = email;
    console.log(email);
    socket.broadcast.emit("email-connected", email);
  });
  socket.on("send-chat-message", message => {
    socket.broadcast.emit("chat-message", {
      message: message,
      name: users[socket.id],
    });
  });
});

//peer
const { ExpressPeerServer } = require("peer");
const { name } = require("ejs");
const peerServer = ExpressPeerServer(https, {
  debug: true,
});

app.use(express.json());
app.use(express.static("public"));
app.use(express.static("jquery"));
app.use(express.static("images"));
app.use(cookieparser());
app.set("view engine", "ejs");
app.set("views", templatePath);
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: "secret",
    cookie: { maxAge: 60000 },
    saveUninitialized: false,
    resave: false,
  })
);

/*app.use(async (req, res, next) => {
  const appointment = await Appointment.find({
    email: req.cookies.emailUser,
  });

  const onlineConsult = await OnlineConsult.find({
    email: req.cookies.emailUser,
  });

  // Modify the appointmentList array to include the enabled property
  const appointmentList = appointment.map(appointment => {
    const currentTime = new Date();
    const appointmentDate = appointment.date;
    const oneHourAhead = new Date(appointmentDate.getTime() + 60 * 60 * 1000); // Add 1 hour to the appointment date
    
    
    const enabled =
      currentTime > appointmentDate && currentTime < oneHourAhead; // Determine if the button should be enabled
    const formattedDate = moment(appointmentDate).format(
      "MMMM Do YYYY, h:mm:ss a"
    ); // Format the date
  });
});*/
const transferAppointmentsToHistory = async (req, res, next) => {
  try {
    // Get the current time
    const currentTime = new Date();

    // Calculate the time 1 hour ago
    const oneHourAgo = new Date(currentTime.getTime() - 60 * 60 * 1000);

    // Find appointments where the date is 1 hour earlier than the current time
    const appointments = await Appointment.find({ date: { $lt: oneHourAgo } });
    const consult = await OnlineConsult.find({ date: { $lt: oneHourAgo } });

    // Transfer appointments to history collection
    await appointmentDone.insertMany(appointments);
    await consultDone.insertMany(consult);

    // Remove transferred appointments from the appointment collection
    await Appointment.deleteMany({
      _id: { $in: appointments.map(appointment => appointment._id) },
    });
    await OnlineConsult.deleteMany({
      _id: { $in: consult.map(OnlineConsult => OnlineConsult._id) },
    });

    console.log("Appointments transferred to history successfully.");
    next();
  } catch (error) {
    console.error("Error transferring appointments to history:", error);
  }
};

function calculateAge(birthdate) {
  const currentDate = new Date();
  const birthdateParts = birthdate.split("-");
  const userBirthdate = new Date(
    birthdateParts[0],
    birthdateParts[1] - 1,
    birthdateParts[2]
  );

  let age = currentDate.getFullYear() - userBirthdate.getFullYear();

  if (
    currentDate.getMonth() < userBirthdate.getMonth() ||
    (currentDate.getMonth() === userBirthdate.getMonth() &&
      currentDate.getDate() < userBirthdate.getDate())
  ) {
    age--;
  }

  return age;
}

app.get("/", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/PAppointment", async (req, res) => {
  try {
    // Fetch disabled dates and times from MongoDB Atlas
    const disabledDateTimes = await Appointment.find();

    res.render("PAppointment", { disabledDateTimes });
  } catch (err) {
    console.error("Error fetching disabled dates and times:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/POnlineConsult", async (req, res) => {
  try {
    const doctors = await doctorInfo.find();
    res.render("POnlineConsult", { doctors });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error fetching doctors.");
  }
});
app.get("/loginSuccess", (req, res) => {
  res.render("loginSuccess");
});
app.get("/PHome", (req, res) => {
  res.render("Phome");
});
app.get("/DHome", async (req, res) => {
  try {
    const doctors = await doctorInfo.find();
    console.log(doctors);
    res.render("DHome", { doctors });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error fetching doctors.");
  }
});
app.get("/DHistory", async (req, res) => {
  const history = await appointmentDone.find({});
  const consultHistory = await consultDone.find({});

  const historyList = history.map(history => {
    const historyDate = history.date;
    const formattedDate = moment(historyDate).format("MMMM Do YYYY, h:mm:ss a"); // Format the date

    return {
      ...history.toObject(),
      formattedDate,
    };
  });
  const consultHistoryList = consultHistory.map(consultHistory => {
    const historyDate = history.date;
    const formattedDate = moment(historyDate).format("MMMM Do YYYY, h:mm:ss a"); // Format the date

    return {
      ...consultHistory.toObject(),
      formattedDate,
    };
  });

  res.render("DHistory", { historyList, consultHistoryList });
});
app.get("/DAppointment", async (req, res) => {
  try {
    const appointment = await Appointment.find({});

    const appointmentList = appointment.map(appointment => {
      const currentTime = new Date();
      const appointmentDate = appointment.date;
      const oneHourAhead = new Date(appointmentDate.getTime() + 60 * 60 * 1000); // Add 1 hour to the appointment date
      const enabled =
        currentTime > appointmentDate && currentTime < oneHourAhead; // Determine if the button should be enabled
      const formattedDate = moment(appointmentDate).format(
        "MMMM Do YYYY, h:mm:ss a"
      ); // Format the date

      return {
        ...appointment.toObject(),
        enabled,
        formattedDate,
      };
    });

    res.render("DAppointment", { appointmentList });
  } catch (error) {
    res.status(500).json({ message: error.message });
    console.log(error);
  }
});

app.get("/DOnlineConsult", async (req, res) => {
  try {
    const onlineConsult = await OnlineConsult.find({});

    const onlineConsultList = onlineConsult.map(onlineConsult => {
      const currentTime = new Date();
      const onlineConsultDate = onlineConsult.date;
      const oneHourAhead = new Date(
        onlineConsultDate.getTime() + 60 * 60 * 1000
      ); // Add 1 hour to the appointment date
      const enabled =
        currentTime > onlineConsultDate && currentTime < oneHourAhead; // Determine if the button should be enabled
      const formattedDate = moment(onlineConsultDate).format(
        "MMMM Do YYYY, h:mm:ss a"
      ); // Format the date

      return {
        ...onlineConsult.toObject(),
        enabled,
        formattedDate,
      };
    });

    res.render("DOnlineConsult", { onlineConsultList });
  } catch (error) {
    res.status(500).json({ message: error.message });
    console.log(error);
  }
});
app.get("/DoctorInfo", (req, res) => {
  res.render("DoctorInfo");
});
app.get("/loginFailed", (req, res) => {
  res.render("loginFailed");
});
app.get("/bookFailed", (req, res) => {
  res.render("bookFailed");
});
app.get("/verify", (req, res) => {
  res.render("verify");
});
app.get("/chatroom", async (req, res) => {
  const email = req.cookies.emailUser;
  const username = req.cookies.name;
  res.render(`chatroom`, { username: username, email: email });
});
app.get("/room", (req, res) => {
  res.redirect(`/room${uuidv4()}`);
});

app.get("/room:room", (req, res) => {
  res.render("room", {
    roomId: "room" + req.params.room,
    name: req.cookies.name,
    email: req.cookies.emailUser,
    paypalClientId: process.env.PAYPAL_CLIENT_ID,
  });
});

app.get("/Droom", (req, res) => {
  res.redirect(`/Droom${uuidv4()}`);
});
app.get("/Droom:Droom", (req, res) => {
  res.render("Droom", {
    roomId: "Droom" + req.params.Droom,
    name: req.cookies.name,
  });
});
app.get("/history", async (req, res) => {
  const appointmentHistory = await appointmentDone.find({
    email: req.cookies.emailUser,
  });
  const consultHistory = await consultDone.find({
    email: req.cookies.emailUser,
  });

  const historyList = appointmentHistory.map(appointmentHistory => {
    const historyDate = appointmentHistory.date;
    const formattedDate = moment(historyDate).format("MMMM Do YYYY, h:mm:ss a"); // Format the date

    return {
      ...appointmentHistory.toObject(),
      formattedDate,
    };
  });

  const consultHistoryList = consultHistory.map(consultHistory => {
    const historyDate = consultHistory.date;
    const formattedDate = moment(historyDate).format("MMMM Do YYYY, h:mm:ss a"); // Format the date

    return {
      ...consultHistory.toObject(),
      formattedDate,
    };
  });

  res.render("history", { historyList, consultHistoryList });
});

app.get("/myappointment", transferAppointmentsToHistory, async (req, res) => {
  try {
    const appointment = await Appointment.find({
      email: req.cookies.emailUser,
    });

    const onlineConsult = await OnlineConsult.find({
      email: req.cookies.emailUser,
    });
    const age = req.cookies.age;
    const fullname = req.cookies.name;
    const gender = req.cookies.gender;

    // Modify the appointmentList array to include the enabled property
    const appointmentList = appointment.map(appointment => {
      const currentTime = new Date();
      const appointmentDate = appointment.date;
      const oneHourAhead = new Date(appointmentDate.getTime() + 60 * 60 * 1000); // Add 1 hour to the appointment date
      const enabled =
        currentTime > appointmentDate && currentTime < oneHourAhead; // Determine if the button should be enabled
      const formattedDate = moment(appointmentDate).format(
        "MMMM Do YYYY, h:mm:ss a"
      ); // Format the date

      return {
        ...appointment.toObject(),
        enabled,
        formattedDate,
      };
    });

    const onlineConsultList = onlineConsult.map(onlineConsult => {
      const currentTime = new Date();
      const onlineConsultDate = onlineConsult.date;
      const oneHourAhead = new Date(
        onlineConsultDate.getTime() + 60 * 60 * 1000
      );
      const enabled =
        onlineConsult.paid === "Paid" &&
        currentTime > onlineConsultDate &&
        currentTime < oneHourAhead;
      const formattedDate = moment(onlineConsultDate).format(
        "MMMM Do YYYY, h:mm:ss a"
      );
      const paymentEnabled = onlineConsult.status === "Approved";

      return {
        ...onlineConsult.toObject(),
        enabled,
        formattedDate,
        paymentEnabled,
      };
    });

    res.render("myappointment", {
      appointmentList,
      onlineConsultList,
      age,
      fullname,
      gender,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
    console.log(error);
  }
});

/*-----REGISTER------*/
app.post("/register", async (req, res) => {
  try {
    const userBirthdate = req.body.birthdate;
    const userAge = calculateAge(userBirthdate);
    const data = {
      first_name: req.body.firstName,
      last_name: req.body.lastName,
      full_name: req.body.firstName + " " + req.body.lastName,
      contact_number: req.body.contactNumber,
      address: req.body.address,
      birthdate: new Date(req.body.birthdate),
      age: userAge,
      gender: req.body.gender,
      email: req.body.email,
      password: req.body.password,
      isVerified: false,
      emailToken: crypto.randomBytes(64).toString("hex"),
    };
    const salt = await bcrypt.genSalt(10);
    const hashpassword = await bcrypt.hash(data.password, salt);
    data.password = hashpassword;
    await Register.insertMany([data]);

    //send verification to the user
    var mailOptions = {
      from: ' "Verify your email" <dummy8270@gmail.com',
      to: data.email,
      subject: "dummy8270 -verify your email",
      html: `<h2> ${data.first_name}! Thanks for registering on our site </h2>
            <h4> Please verify your email to continue..</h4>
            <a href="https://${req.headers.host}/login/verify-email?token=${data.emailToken}">Verify Your Email</a>`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        console.log("Verification email is sent to your gmail account");
      }
    });
    res.render("login");
  } catch (err) {
    console.log(err);
  }
});

app.get("/login/verify-email", async (req, res) => {
  try {
    const token = req.query.token;
    const user = await Register.findOne({ emailToken: token });
    if (user) {
      user.emailToken = null;
      user.isVerified = true;
      user.userRole = "0";
      await user.save();
      console.log("email is verified");
      res.redirect("/");
    } else {
      res.redirect("/register");
      console.log("email is not verified");
    }
  } catch (err) {
    console.log(err);
  }
});

/*-----LOGIN-----*/
app.post("/login", verifyEmail, async (req, res) => {
  try {
    const { email, password } = req.body;
    const check = await Register.findOne({ email: email });
    if (check) {
      const match = await bcrypt.compare(password, check.password);
      if (match) {
        if (check.userRole === "1") {
          //create token
          const doctors = await doctorInfo.find();
          const token = createToken(check._id);
          const user = check.email;
          const name = check.first_name;
          const age = check.age;
          //store token in cookie
          res.cookie("access-token", token);
          res.cookie("emailUser", user);
          res.cookie("name", name);
          res.cookie("age", age);
          res.render("DHome", { doctors });
        } else if (check.userRole === "0") {
          //create token
          const token = createToken(check._id);
          const user = check.email;
          const name = check.full_name;
          const age = check.age;
          const gender = check.gender;
          //store token in cookie
          res.cookie("access-token", token);
          res.cookie("emailUser", user);
          res.cookie("name", name);
          res.cookie("age", age);
          res.cookie("gender", gender);
          res.redirect("loginSuccess");
        }
      } else {
        console.log("invalid password");
        res.redirect("loginFailed");
      }
    }
  } catch (err) {
    res.redirect("loginFailed");
    console.log(err);
  }
});

/*---APPOINTMENT----*/
app.post("/PAppointment", upload.single("image"), async (req, res) => {
  const data = {
    name: req.cookies.name,
    age: req.body.age,
    date: new Date(req.body.date),
    description: req.body.description,
    services: req.body.services,
    image: {
      data: req.file.buffer,
      contentType: req.file.mimetype,
    },
    email: req.cookies.emailUser,
  };
  console.log(data);

  await Appointment.insertMany([data]);
  res.render("PHome");
});

/*---ONLINE CONSULTATION----*/
app.post("/POnlineConsult", upload.single("image"), async (req, res) => {
  const checkdate = req.body.date;
  const data = {
    name: req.cookies.name,
    date: req.body.date,
    description: req.body.description,
    email: req.cookies.emailUser,
    age: req.cookies.age,
    gender: req.cookies.gender,
    isVerified: false,
    paid: "Unpaid",
    status: "Waiting to Approved",
  };
  try {
    const existingAppointment = await OnlineConsult.findOne({
      date: checkdate,
    });
    if (existingAppointment) {
      // Appointment already booked
      res.redirect("bookFailed");
      console.log("Booked Already");
    } else {
      console.log(data);
      await OnlineConsult.insertMany([data]);
      console.log(data);
      res.redirect("PHome");
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/prescription", uploadprescription.single("image"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("No image uploaded.");
  }
  const picturePath = path.join(__dirname, "pictures", req.file.originalname);
  fs.renameSync(req.file.path, picturePath);

  const data = {
    name: req.body.email,
    picture: req.file.originalname,
  };
  //send verification to the user
  var mailOptions = {
    from: ' "Verify your email" <dummy8270@gmail.com>',
    to: data.name,
    subject: "Dr. Ryan -verify your email",
    html: `<h2> Thanks for Consulting in Dr. Ryan Dental Clinic here's your prescription! </h2>`,
    attachments: [
      {
        filename: data.picture,
        path: `./src/pictures/${data.picture}`,
      },
    ],
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Prescription has been sent to the patient");
      res.redirect("Droom");
    }
  });
});

app.post("/doctorInfo", async (req, res) => {
  const fullName = req.body.doctorName;
  const date = req.body.date;
  const consultation_fee = req.body.consultationFee;

  doctorInfo
    .findOneAndUpdate(
      {},
      { fullName, date, consultation_fee },
      { upsert: true }
    )
    .then(() => {
      console.log("Data updated successfully");
      res.redirect("DHome");
    })
    .catch(error => {
      console.log("Error updating data:", error);
      res.status(500).send("Error updating data");
    });
});

app.post("/cancel-appointment", async (req, res) => {
  try {
    //await client.connect();
    //const db = client.db("<database-name>");
    const { appointmentId } = req.body;

    // Retrieve the appointment to be canceled
    const appointment = await Appointment.findOne({ _id: appointmentId });
    const onlineConsult = await OnlineConsult.findOne({ _id: appointmentId });

    if (appointment) {
      // Transfer the appointment to the history collection
      await appointmentDone.insertMany(appointment);
      // Delete the appointment from the original collection
      await Appointment.deleteMany({ _id: appointmentId });
    } else {
      await consultDone.insertMany(onlineConsult);
      await OnlineConsult.deleteMany({ _id: appointmentId });
    }
    res.sendStatus(200);
  } catch (error) {
    console.error("Error canceling appointment:", error);
    res.status(500).send("An error occurred");
  }
});

app.post("/approve-appointment", async (req, res) => {
  try {
    //await client.connect();
    //const db = client.db("<database-name>");
    const { appointmentId } = req.body;

    // Retrieve the appointment to be canceled
    const onlineConsult = await OnlineConsult.findOne({ _id: appointmentId });

    if (onlineConsult) {
      (onlineConsult.status = "Approved"),
        (onlineConsult.isVerified = true),
        await onlineConsult.save();
    } else {
      res.send("No appointmentId match to be approve");
    }
    res.sendStatus(200);
  } catch (error) {
    console.error("Error canceling appointment:", error);
    res.status(500).send("An error occurred");
  }
});

app.get("/disabled-dates", async (req, res) => {
  try {
    // Fetch the appointments from the database
    const appointments = await Appointment.find({}, { datetime: 1 });

    // Extract the dates and times from the appointments
    const disabledDates = [];
    const disabledTimes = [];
    appointments.forEach(appointment => {
      const appointmentDate = appointment.datetime;
      const appointmentTime = appointment.datetime;
      const formattedDate = moment(appointmentDate).format(
        "MMMM Do YYYY, h:mm:ss a"
      ); // Format the date
      const formattedTime = moment(appointmentTime).format(
        "MMMM Do YYYY, h:mm:ss a"
      ); // Format the date
      disabledDates.push(formattedDate);
      disabledTimes.push(formattedTime);
    });

    res.json({ disabledDates, disabledTimes });
    console.log(disabledDates, disabledTimes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

let consult; // Declare consult variable outside of the route

app.post("/pay", async (req, res) => {
  const appointmentId = req.body.appointmentId;
  consult = await OnlineConsult.findOne({ _id: appointmentId }); // Retrieve consult data
  const create_payment_json = {
    intent: "sale",
    payer: {
      payment_method: "paypal",
    },
    redirect_urls: {
      return_url: "https://localhost:3000/success",
      cancel_url: "https://localhost:3000/cancel",
    },
    transactions: [
      {
        item_list: {
          items: [
            {
              name: "Consultation Fee",
              sku: "55",
              price: "1.00",
              currency: "PHP",
              quantity: 1,
            },
          ],
        },
        amount: {
          currency: "PHP",
          total: "1.00",
        },
        description: "Best Dentist Ever",
      },
    ],
  };

  app.get("/success", async (req, res) => {
    const payerId = req.query.PayerID;
    const paymentId = req.query.paymentId;

    try {
      consult.paid = "Paid";
      await consult.save();
    } catch (error) {
      console.log(error);
    }

    const execute_payment_json = {
      payer_id: payerId,
      transactions: [
        {
          amount: {
            currency: "PHP",
            total: "1.00",
          },
        },
      ],
    };

    paypal.payment.execute(
      paymentId,
      execute_payment_json,
      function (error, payment) {
        if (error) {
          console.log(error.response);
          throw error;
        } else {
          console.log(JSON.stringify(payment));
          res.redirect("myappointment");
        }
      }
    );
  });

  paypal.payment.create(create_payment_json, function (error, payment) {
    if (error) {
      throw error;
    } else {
      for (let i = 0; i < payment.links.length; i++) {
        if (payment.links[i].rel === "approval_url") {
          res.redirect(payment.links[i].href);
        }
      }
    }
  });
});
app.get("/cancel", (req, res) => res.redirect("myappointment"));

app.post(
  "/uploadRecord",
  uploadrecord.single("recording"),
  async (req, res) => {
    const recordingFile = req.file;

    // Save the recording file to MongoDB Atlas
    if (recordingFile) {
      const recording = {
        appointmentId: new ObjectId(), // Generate a unique appointment ID
        recordingPath: recordingFile.path,
        recordingMimetype: recordingFile.mimetype,
      };

      ScreenRecord.insertOne(recording)
        .then(() => {
          console.log("Recording uploaded successfully");
          res.sendStatus(200);
        })
        .catch(error => {
          console.error("Error uploading recording:", error);
          res.sendStatus(500);
        });
    } else {
      res.sendStatus(400);
    }
  }
);

sslServer.listen(3000, () => console.log("secure server running on port 3000"));
