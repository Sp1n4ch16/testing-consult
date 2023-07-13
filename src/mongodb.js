const mongoose = require("mongoose");
const {
  DataSessionInstance,
} = require("twilio/lib/rest/wireless/v1/sim/dataSession");

mongoose.set("strictQuery", false);
mongoose
  .connect(
    "mongodb+srv://admin:admin@consultation.ctwo2ll.mongodb.net/?retryWrites=true&w=majority"
  )
  .then(() => {
    console.log("MongoDB Connected");
  })
  .catch(error => {
    console.log(error);
  });

const registerSchema = new mongoose.Schema(
  {
    first_name: {
      type: String,
      required: [true, "Please enter first name"],
    },
    last_name: {
      type: String,
      required: [true, "Please enter last name"],
    },
    full_name: {
      type: String,
    },
    contact_number: {
      type: String,
      required: [true, "Please enter last name"],
    },
    address: {
      type: String,
      required: [true, "Please enter last name"],
    },
    birthdate: {
      type: Date,
    },
    age: {
      type: String,
    },
    gender: {
      type: String,
    },
    email: {
      type: String,
      required: [true, "Please enter email"],
    },
    password: {
      type: String,
      required: [true, "Please enter password"],
    },
    isVerified: {
      type: Boolean,
    },
    emailToken: {
      type: String,
    },
    userRole: {
      type: String,
    },
    date: {
      type: Date,
      default: Date.now(),
    },
  },
  {
    timestamps: true,
  }
);

const appointmentSchema = mongoose.Schema(
  {
    name: {
      type: String,
    },
    age: {
      type: String,
    },
    date: {
      type: Date,
    },
    description: {
      type: String,
      required: [true, "Please enter description"],
    },
    services: {
      type: String,
      required: [true, "Please enter your services"],
    },
    image: {
      data: Buffer,
      contentType: String,
    },
    email: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

const onlineconsultationSchema = mongoose.Schema(
  {
    name: {
      type: String,
    },
    description: {
      type: String,
    },
    date: {
      type: Date,
    },
    age: {
      type: String,
    },
    gender: {
      type: String,
    },
    email: {
      type: String,
    },
    isVerified: {
      type: Boolean,
    },
    paid: {
      type: String,
    },
    status: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

const doctorSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please enter name"],
    },
    email: {
      type: String,
      required: [true, "Please enter email"],
    },
    password: {
      type: String,
      required: [true, "Please enter password"],
    },
    isVerified: {
      type: Boolean,
    },
  },
  {
    timestamps: true,
  }
);

const appointmentDoneschema = mongoose.Schema(
  {
    name: {
      type: String,
    },
    age: {
      type: String,
    },
    date: {
      type: Date,
    },
    description: {
      type: String,
    },
    services: {
      type: String,
    },
    image: {
      data: Buffer,
      contentType: String,
    },
    email: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

const onlineConsultDoneschema = mongoose.Schema(
  {
    name: {
      type: String,
    },
    age: {
      type: String,
    },
    status: {
      type: String,
    },
    date: {
      type: Date,
    },
    description: {
      type: String,
      required: [true, "Please enter description"],
    },
    image: {
      data: Buffer,
      contentType: String,
    },
    email: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);
const doctorInfoSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
    },
    date: {
      type: Date,
      default: Date.now(),
    },
    consultation_fee: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);
const recordingSchema = new mongoose.Schema({
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  recordingPath: {
    type: String,
    required: true,
  },
  recordingMimetype: {
    type: String,
    required: true,
  },
});

const doctorInfo = new mongoose.model("Doctor Information", doctorInfoSchema);
const Appointment = new mongoose.model("Appointment", appointmentSchema);
const Register = mongoose.model("Register", registerSchema);
const ScreenRecord = new mongoose.model("Screen Record", recordingSchema);
const appointmentDone = new mongoose.model(
  "Appointment-History",
  appointmentDoneschema
);
const consultDone = new mongoose.model(
  "Online Consultation-History",
  onlineConsultDoneschema
);
const OnlineConsult = new mongoose.model(
  "Online Consultation",
  onlineconsultationSchema
);
const Doctor = mongoose.model("Doctor", doctorSchema);
module.exports = {
  Appointment,
  Register,
  OnlineConsult,
  Doctor,
  appointmentDone,
  consultDone,
  doctorInfo,
  ScreenRecord,
};
