const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const https = require('https');
const dns = require("dns");
dns.setDefaultResultOrder("ipv4first");
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const app = express();

// ===== MIDDLEWARE =====
const trustProxyValue = process.env.TRUST_PROXY || (process.env.NODE_ENV === 'production' ? '1' : 'false');
if (trustProxyValue !== 'false') {
  const parsedTrustProxy =
    trustProxyValue === 'true' ? true : Number.isNaN(Number(trustProxyValue)) ? trustProxyValue : Number(trustProxyValue);
  app.set('trust proxy', parsedTrustProxy);
}

app.use(cors());
app.use(express.json());

// ===== DATABASE CONNECTION =====
const MONGODB_URI =
  process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/eduquest';

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
  });

// ===== SCHEMAS & MODELS =====



// Subdocument for questions
const questionSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    question: { type: String, required: true },
    options: { type: [String], default: [] },
    correctAnswer: { type: Number, required: true },
    explanation: { type: String, default: '' }
  },
  { _id: false }
);

// Quest schema
const questSchema = new mongoose.Schema(
  {
    // we keep our own "id" field so frontend doesn't need changes
    id: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    difficulty: { type: String, default: 'Easy' },
    xpReward: { type: Number, default: 0 },
    timeLimit: { type: Number, default: null },
    teacherId: { type: String, default: null },

    questions: { type: [questionSchema], default: [] },
    courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
    courseName: { type: String, required: true },
    section: { type: String }


  },
  { timestamps: true }
);

const COURSE_STATUS = {
  PENDING: 'pending',
  APPROVED: 'approved',
  REJECTED: 'rejected'
};

//Course schema
const courseSchema = new mongoose.Schema({

  name: { type: String, required: true },
  section: { type: String },
  teacherId: { type: String, required: true },
  otpCode: { type: String, required: true },
  status: {
    type: String,
    enum: Object.values(COURSE_STATUS),
    default: COURSE_STATUS.PENDING
  },
  rejectionReason: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  approvedBy: { type: String, default: null }
}, { timestamps: true });
const Course = mongoose.model('Course', courseSchema);


const Quest = mongoose.model('Quest', questSchema);

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true },

    // hashed password
    passwordHash: { type: String, required: true },

    role: {
      type: String,
      enum: ['student', 'teacher', 'admin'],
      required: true
    },

    studentClasses: {
      type: [mongoose.Schema.Types.ObjectId],
      ref: 'Course',
      default: []
    },

    name: { type: String, required: true },

    // teacher-only fields
    subjects: { type: [String], default: [] },

    // optional character link
    characterId: { type: String },
    profilePic: { type: String, default: '' },

    resetPasswordTokenHash: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null }
  },
  { timestamps: true }
);

userSchema.methods.setPassword = async function (plainPassword) {
  const salt = await bcrypt.genSalt(10);
  this.passwordHash = await bcrypt.hash(plainPassword, salt);
};

userSchema.methods.checkPassword = async function (plainPassword) {
  return bcrypt.compare(plainPassword, this.passwordHash);
};

const User = mongoose.model('User', userSchema);

const studentStateSchema = new mongoose.Schema(
  {
    studentId: { type: String, required: true, unique: true },
    character: { type: Object, default: null },

    // progress per quest: { questId: score }
    progress: {
      type: Map,
      of: Number,
      default: {}
    },

    // level & xp
    level: { type: Number, default: 1 },
    xp: { type: Number, default: 0 },

    // inventory: array of any item objects you already use
    inventory: {
      type: [Object],
      default: []
    },

    // achievements: array of objects
    achievements: {
      type: [Object],
      default: []
    },

    // student classes: array of teacher IDs
    studentClasses: {
      type: [String],
      default: [] // Add studentClasses field
    }
  },
  { timestamps: true }
);

const StudentState = mongoose.model('StudentState', studentStateSchema);

const reportSchema = new mongoose.Schema({
  reporterId: { type: String, required: true },
  reporterName: { type: String, required: true },
  teacherId: { type: String, required: true },
  teacherName: { type: String, required: true },
  courseId: { type: String, default: null },
  courseName: { type: String, default: null },
  category: { type: String, required: true },
  subject: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, default: 'pending' },
  adminNotes: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Report = mongoose.model('Report', reportSchema);

// Add this schema after the Report schema (around line 190)
const notificationSchema = new mongoose.Schema({
  recipientId: { type: String, required: true }, // who receives the notification
  type: { type: String, required: true }, // 'report', 'course_approved', etc.
  title: { type: String, required: true },
  message: { type: String, required: true },
  relatedId: { type: String, default: null }, // report ID, course ID, etc.
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Notification = mongoose.model('Notification', notificationSchema);

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || req.socket?.remoteAddress || 'unknown',
  message: { message: 'Too many requests. Please try again later.' }
});

let smtpConnectHostsPromise = null;

async function resolveSmtpConnectHosts() {
  if (smtpConnectHostsPromise) {
    return smtpConnectHostsPromise;
  }

  const smtpHost = process.env.SMTP_HOST;
  smtpConnectHostsPromise = (async () => {
    if (!smtpHost) {
      return [];
    }

    try {
      const ipv4Addresses = await dns.promises.resolve4(smtpHost);
      if (Array.isArray(ipv4Addresses) && ipv4Addresses.length > 0) {
        return ipv4Addresses;
      }
    } catch (_err) {
      // Fall back to the configured hostname if IPv4 resolution is unavailable.
    }

    return [smtpHost];
  })();

  return smtpConnectHostsPromise;
}

function createSmtpTransport(connectHost) {
  return nodemailer.createTransport({
    host: connectHost,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE) === 'true',
    family: Number(process.env.SMTP_FAMILY || 4),
    connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT || 15000),
    greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT || 15000),
    socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT || 20000),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    tls: {
      servername: process.env.SMTP_HOST || undefined
    }
  });
}

async function withSmtpTransport(workFn) {
  const hosts = await resolveSmtpConnectHosts();
  const candidates = hosts.length > 0 ? hosts : [process.env.SMTP_HOST].filter(Boolean);
  let lastErr = null;

  for (const connectHost of candidates) {
    const transporter = createSmtpTransport(connectHost);
    try {
      return await workFn(transporter, connectHost);
    } catch (err) {
      lastErr = err;
      console.error(`SMTP connection attempt failed for ${connectHost}:${Number(process.env.SMTP_PORT || 587)}:`, err.message);
    }
  }

  throw lastErr || new Error('No SMTP host available');
}

function parseMailFrom(rawFromValue) {
  const fallback = process.env.SMTP_USER || '';
  const raw = String(rawFromValue || fallback).trim();
  const match = raw.match(/^(.*)<([^>]+)>$/);
  if (!match) {
    return { email: raw, name: '' };
  }
  return {
    name: String(match[1] || '').replace(/^"|"$/g, '').trim(),
    email: String(match[2] || '').trim()
  };
}

async function sendEmailViaBrevo({ toEmail, subject, text, html }) {
  const apiKey = process.env.BREVO_API_KEY;
  if (!apiKey) {
    throw new Error('BREVO_API_KEY is not configured');
  }

  const sender = parseMailFrom(process.env.MAIL_FROM || process.env.SMTP_FROM);
  if (!sender.email) {
    throw new Error('MAIL_FROM or SMTP_FROM must include a sender email');
  }

  const payload = JSON.stringify({
    sender: sender.name ? { email: sender.email, name: sender.name } : { email: sender.email },
    to: [{ email: toEmail }],
    subject,
    textContent: text,
    htmlContent: html
  });

  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        hostname: 'api.brevo.com',
        path: '/v3/smtp/email',
        method: 'POST',
        headers: {
          accept: 'application/json',
          'api-key': apiKey,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload)
        }
      },
      (response) => {
        let body = '';
        response.on('data', (chunk) => {
          body += chunk;
        });
        response.on('end', () => {
          if (response.statusCode >= 200 && response.statusCode < 300) {
            resolve();
            return;
          }
          reject(new Error(`Brevo API ${response.statusCode}: ${body || 'Unknown error'}`));
        });
      }
    );

    request.on('error', reject);
    request.write(payload);
    request.end();
  });
}

const mailProvider = String(process.env.MAIL_PROVIDER || (process.env.BREVO_API_KEY ? 'brevo' : 'smtp')).toLowerCase();
const frontendBaseUrl = process.env.FRONTEND_URL || process.env.CLIENT_URL || 'http://localhost:3000';

if (mailProvider === 'brevo') {
  if (!process.env.BREVO_API_KEY) {
    console.warn('MAIL_PROVIDER=brevo but BREVO_API_KEY is missing. Forgot-password emails will fail.');
  } else {
    console.log('Mail provider ready: Brevo API');
  }
} else {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn('SMTP env is incomplete. Forgot-password emails will fail until SMTP vars are set.');
  } else {
    withSmtpTransport(
      (transporter, connectHost) =>
        new Promise((resolve, reject) => {
          transporter.verify((err) => {
            if (err) {
              reject(err);
              return;
            }
            resolve(connectHost);
          });
        })
    )
      .then((connectHost) => {
        console.log(`SMTP transporter is ready (host=${connectHost}, family=${Number(process.env.SMTP_FAMILY || 4)})`);
      })
      .catch((err) => {
        console.error('SMTP verify failed:', err.message);
      });
  }
}

function createPasswordResetCode() {
  const rawCode = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const tokenHash = crypto.createHash('sha256').update(rawCode).digest('hex');
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  return { rawCode, tokenHash, expiresAt };
}

async function sendPasswordResetEmail(toEmail, rawCode) {
  const subject = 'EduQuest Password Reset Code';
  const text = `Your EduQuest password reset code is: ${rawCode}\nThis code expires in 15 minutes.`;
  const html = `
    <p>Your EduQuest password reset code is:</p>
    <p style="font-size: 24px; font-weight: 700; letter-spacing: 4px;">${rawCode}</p>
    <p>This code expires in 15 minutes.</p>
  `;

  if (mailProvider === 'brevo') {
    await sendEmailViaBrevo({ toEmail, subject, text, html });
    return;
  }

  await withSmtpTransport((transporter) =>
    transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: toEmail,
      subject,
      text,
      html
    })
  );
}


  function generateJwt(user) {
    return jwt.sign(
      {
        userId: user._id.toString(),
        role: user.role,
        username: user.username
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || '30d'
      }
    );
  }

  function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.user = payload; // { userId, role, username, iat, exp }
      next();
    } catch (err) {
      console.error('JWT verify error:', err);
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  }

  function adminOnly(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin only' });
    }
    next();
  }


  function generateTeacherOtp(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let otp = '';
    for (let i = 0; i < length; i++) {
      otp += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return otp;
  }

  // ===== ROUTES =====

  const forgotPasswordHandler = async (req, res) => {
    try {
      const { identifier } = req.body; // email or username
      if (!identifier || !String(identifier).trim()) {
        return res.status(200).json({
          message: 'If an account exists, a reset code has been sent.'
        });
      }

      const value = String(identifier).trim();
      const user = await User.findOne({
        $or: [{ email: value.toLowerCase() }, { username: value }]
      });

      // Always return generic message to prevent account enumeration
      if (!user) {
        return res.status(200).json({
          message: 'If an account exists, a reset code has been sent.'
        });
      }

      const { rawCode, tokenHash, expiresAt } = createPasswordResetCode();
      user.resetPasswordTokenHash = tokenHash;
      user.resetPasswordExpires = expiresAt;
      await user.save();

      setImmediate(() => {
        sendPasswordResetEmail(user.email, rawCode).catch((mailErr) => {
          console.error(`Forgot password mail send failed for ${user.email}:`, mailErr.message);
        });
      });

      return res.status(200).json({
        message: 'If an account exists, a reset code has been sent.'
      });
    } catch (err) {
      console.error('Forgot password error:', err.message);
      return res.status(200).json({
        message: 'If an account exists, a reset code has been sent.'
      });
    }
  };

  app.post(
    ['/api/auth/forgot-password', '/auth/forgot-password', '/forgot-password'],
    forgotPasswordLimiter,
    forgotPasswordHandler
  );

  app.post('/api/auth/reset-password', async (req, res) => {
    try {
      const { otp, token, newPassword } = req.body;
      const codeOrToken = String(otp || token || '').trim();

      if (!codeOrToken || !newPassword || String(newPassword).length < 8) {
        return res.status(400).json({ message: 'Invalid reset code or password too short' });
      }

      const tokenHash = crypto.createHash('sha256').update(codeOrToken).digest('hex');

      const user = await User.findOne({
        resetPasswordTokenHash: tokenHash,
        resetPasswordExpires: { $gt: new Date() }
      });

      if (!user) {
        return res.status(400).json({ message: 'Reset code is invalid or expired' });
      }

      await user.setPassword(String(newPassword));
      user.resetPasswordTokenHash = null;
      user.resetPasswordExpires = null;
      await user.save();

      return res.json({ message: 'Password reset successful' });
    } catch (err) {
      console.error('Reset password error:', err);
      return res.status(500).json({ message: 'Failed to reset password' });
    }
  });


  // Create a report
  app.post('/api/reports', authMiddleware, async (req, res) => {
    try {
      const { reporterId, reporterName, teacherId, teacherName, courseId, courseName, category, subject, description } = req.body;

      if (!reporterId || !teacherId || !category || !subject || !description) {
        return res.status(400).json({ message: 'Missing required fields' });
      }

      const report = new Report({
        reporterId,
        reporterName,
        teacherId,
        teacherName,
        courseId,
        courseName,
        category,
        subject,
        description
      });

      const saved = await report.save();

      // CREATE NOTIFICATION FOR TEACHER
      const notification = new Notification({
        recipientId: teacherId,
        type: 'report',
        title: 'New Student Report',
        message: `${reporterName} has submitted a report about you in "${courseName || 'a course'}"`,
        relatedId: saved._id.toString()
      });

      await notification.save();

      res.status(201).json(saved);
    } catch (err) {
      console.error('Error creating report:', err);
      res.status(500).json({ message: 'Failed to create report' });
    }
  });

  // Get teacher notifications
  app.get('/api/notifications/:userId', authMiddleware, async (req, res) => {
    try {
      const { userId } = req.params;

      if (req.user.userId !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not allowed' });
      }

      const notifications = await Notification.find({ recipientId: userId })
        .sort({ createdAt: -1 })
        .lean();

      res.json(notifications);
    } catch (err) {
      console.error('Error fetching notifications:', err);
      res.status(500).json({ message: 'Failed to fetch notifications' });
    }
  });

  // Mark notification as read
  app.put('/api/notifications/:notificationId/read', authMiddleware, async (req, res) => {
    try {
      const { notificationId } = req.params;

      const updated = await Notification.findByIdAndUpdate(
        notificationId,
        { read: true },
        { new: true }
      ).lean();

      if (!updated) {
        return res.status(404).json({ message: 'Notification not found' });
      }

      res.json(updated);
    } catch (err) {
      console.error('Error updating notification:', err);
      res.status(500).json({ message: 'Failed to update notification' });
    }
  });

  // Mark all notifications as read
  app.put('/api/notifications/:userId/read-all', authMiddleware, async (req, res) => {
    try {
      const { userId } = req.params;

      if (req.user.userId !== userId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not allowed' });
      }

      await Notification.updateMany(
        { recipientId: userId, read: false },
        { read: true }
      );

      res.json({ message: 'All notifications marked as read' });
    } catch (err) {
      console.error('Error marking notifications as read:', err);
      res.status(500).json({ message: 'Failed to update notifications' });
    }
  });

  // Get all reports (admin only)
  app.get('/api/admin/reports', authMiddleware, adminOnly, async (req, res) => {
    try {
      const reports = await Report.find().sort({ createdAt: -1 }).lean();
      res.json(reports);
    } catch (err) {
      console.error('Error fetching reports:', err);
      res.status(500).json({ message: 'Failed to fetch reports' });
    }
  });

  // Update report status (admin only)
  // Update report status endpoint - add notifications
  app.put('/api/admin/reports/:reportId', authMiddleware, adminOnly, async (req, res) => {
    try {
      const { reportId } = req.params;
      const { status, adminNotes } = req.body;

      const report = await Report.findByIdAndUpdate(
        reportId,
        { status, adminNotes, updatedAt: new Date() },
        { new: true }
      ).lean();

      if (!report) {
        return res.status(404).json({ message: 'Report not found' });
      }

      // CREATE NOTIFICATION FOR TEACHER ONLY IF STATUS IS 'REVIEWED' OR 'RESOLVED'
      if (status === 'resolved') {
        const notification = new Notification({
          recipientId: report.teacherId,
          type: 'report_resolved',
          title: 'Report Investigation Complete',
          message: `A report has been investigated and resolved.`,
          relatedId: report._id.toString()
        });

        await notification.save();
      }

      res.json(report);
    } catch (err) {
      console.error('Error updating report:', err);
      res.status(500).json({ message: 'Failed to update report' });
    }
  });

  app.get('/api/courses/:courseId/leaderboard', authMiddleware, async (req, res) => {
    try {
      const { courseId } = req.params;

      const course = await Course.findById(courseId).lean();
      if (!course) {
        return res.status(404).json({ message: 'Course not found' });
      }

      if (req.user.role === 'teacher' && String(course.teacherId) !== String(req.user.userId)) {
        return res.status(403).json({ message: 'Not allowed' });
      }

      if (req.user.role === 'student') {
        const me = await User.findById(req.user.userId).select('studentClasses').lean();
        const enrolled = (me?.studentClasses || []).some((cid) => String(cid) === String(courseId));
        if (!enrolled) {
          return res.status(403).json({ message: 'Not allowed' });
        }
      }

      const students = await User.find({ role: 'student', studentClasses: courseId })
        .select('_id username name profilePic')
        .lean();

      const studentIds = students.map((s) => s._id.toString());

      const states = await StudentState.find({ studentId: { $in: studentIds } })
        .select('studentId level xp character')
        .lean();

      const stateByStudentId = new Map(states.map((s) => [String(s.studentId), s]));

      const leaderboard = students
        .map((student) => {
          const studentId = student._id.toString();
          const state = stateByStudentId.get(studentId);
          const character = state?.character || null;

          return {
            id: studentId,
            name: student.name || student.username,
            class: character?.class || 'Adventurer',
            avatar: character?.avatar || student.profilePic || '',
            level: typeof state?.level === 'number' ? state.level : 1,
            xp: typeof state?.xp === 'number' ? state.xp : 0
          };
        })
        .sort((a, b) => {
          if (b.level !== a.level) return b.level - a.level;
          return b.xp - a.xp;
        });

      res.json({
        courseId: course._id.toString(),
        courseName: course.name,
        section: course.section || '',
        leaderboard
      });
    } catch (err) {
      console.error('Error fetching leaderboard:', err);
      res.status(500).json({ message: 'Failed to fetch leaderboard' });
    }
  });



  // Course routes
  app.get('/api/courses', async (req, res) => {
    try {
      const courses = await Course.find({ status: COURSE_STATUS.APPROVED }).lean();
      res.json(courses);
    } catch (err) {
      console.error('Error fetching courses:', err);
      res.status(500).json({ message: 'Failed to fetch courses' });
    }
  });

  //Get all courses for a teacher
  app.get('/api/teachers/:teacherId/courses', authMiddleware, async (req, res) => {
    try {
      if (req.user.userId !== req.params.teacherId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not allowed' });
      }
      const courses = await Course.find({ teacherId: req.params.teacherId }).lean();
      res.json(courses);
    } catch (err) {
      console.error('Error fetching courses:', err);
      res.status(500).json({ message: 'Failed to fetch courses' });
    }
  });

  // Create a new course for a teacher
  app.post('/api/teachers/:teacherId/courses', authMiddleware, async (req, res) => {
    try {
      if (req.user.userId !== req.params.teacherId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not allowed' });
      }
      const { name, section } = req.body;
      if (!name || !name.trim()) {
        return res.status(400).json({ message: 'Course name is required' });
      }
      const course = new Course({
        name: name.trim(),
        section: section ? section.trim() : '',
        teacherId: req.params.teacherId,
        otpCode: generateTeacherOtp()
      });
      const saved = await course.save();
      res.status(201).json(saved);
    } catch (err) {
      console.error('Error creating course:', err);
      res.status(500).json({ message: 'Failed to create course' });
    }
  });

  // Update a course
  app.put('/api/teachers/:teacherId/courses/:courseId', authMiddleware, async (req, res) => {
    try {
      if (req.user.userId !== req.params.teacherId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not allowed' });
      }
      const { name, section } = req.body;
      if (!name || !name.trim()) {
        return res.status(400).json({ message: 'Course name is required' });
      }
      const updated = await Course.findOneAndUpdate(
        { _id: req.params.courseId, teacherId: req.params.teacherId },
        { name: name.trim(), section: section ? section.trim() : '', otpCode: generateTeacherOtp() },
        { new: true }
      ).lean();
      if (!updated) {
        return res.status(404).json({ message: 'Course not found' });
      }
      res.json(updated);
    } catch (err) {
      console.error('Error updating course:', err);
      res.status(500).json({ message: 'Failed to update course' });
    }
  });

  // Delete a course + cleanup quests + cleanup enrollments
  app.delete('/api/teachers/:teacherId/courses/:courseId', authMiddleware, async (req, res) => {
    try {
      const { teacherId, courseId } = req.params;

      if (req.user.userId !== teacherId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not allowed' });
      }

      // ensure course exists and belongs to teacher
      const course = await Course.findOne({ _id: courseId, teacherId }).lean();
      if (!course) {
        return res.status(404).json({ message: 'Course not found' });
      }

      // 1) delete quests for this course
      await Quest.deleteMany({ courseId });

      // 2) remove course from students (User.studentClasses is ObjectId[])
      await User.updateMany(
        { studentClasses: courseId },
        { $pull: { studentClasses: courseId } }
      );

      // 3) remove course from student states (StudentState.studentClasses is String[])
      await StudentState.updateMany(
        { studentClasses: String(courseId) },
        { $pull: { studentClasses: String(courseId) } }
      );

      // 4) delete the course
      await Course.deleteOne({ _id: courseId, teacherId });

      res.json({ message: 'Course deleted with related quests and enrollments cleaned', id: courseId });
    } catch (err) {
      console.error('Error deleting course:', err);
      res.status(500).json({ message: 'Failed to delete course' });
    }
  });

  // ===== AUTH ROUTES =====


  app.put('/api/users/:id/profile-pic', authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const { profilePic } = req.body;

      if (req.user.userId !== id) {
        return res.status(403).json({ message: 'Not allowed' });
      }

      const updatedUser = await User.findByIdAndUpdate(
        id,
        { profilePic },
        { new: true }
      ).lean();

      if (!updatedUser) {
        return res.status(404).json({ message: 'User not found' });
      }

      const { passwordHash, ...userSafe } = updatedUser;
      res.json(userSafe);
    } catch (err) {
      console.error('Error updating profilePic:', err);
      res.status(500).json({ message: 'Failed to update profile picture' });
    }
  });

  app.put('/api/users/:id/profile', authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const { name, subjects } = req.body;

      if (req.user.userId !== id) {
        return res.status(403).json({ message: 'Not allowed' });
      }

      const updateDoc = {};
      if (typeof name === 'string' && name.trim()) updateDoc.name = name.trim();

      // subjects can be string or array
      if (typeof subjects === 'string') {
        updateDoc.subjects = [subjects.trim()].filter(Boolean);
      } else if (Array.isArray(subjects)) {
        updateDoc.subjects = subjects.map(s => String(s).trim()).filter(Boolean);
      }

      const updatedUser = await User.findByIdAndUpdate(
        id,
        { $set: updateDoc },
        { new: true }
      ).lean();

      if (!updatedUser) return res.status(404).json({ message: 'User not found' });

      const { passwordHash, ...userSafe } = updatedUser;
      res.json(userSafe);
    } catch (err) {
      console.error('Error updating profile:', err);
      res.status(500).json({ message: 'Failed to update profile' });
    }
  });


  app.put('/api/users/:id/character', authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const { characterId } = req.body;

      if (!characterId) {
        return res.status(400).json({ message: 'characterId is required' });
      }

      // only allow the logged-in user to update their own character
      if (req.user.userId !== id) {
        return res.status(403).json({ message: 'Not allowed' });
      }

      const updatedUser = await User.findByIdAndUpdate(
        id,
        { characterId },
        { new: true }
      ).lean();

      if (!updatedUser) {
        return res.status(404).json({ message: 'User not found' });
      }

      const { passwordHash, ...userSafe } = updatedUser;
      res.json(userSafe);
    } catch (err) {
      console.error('Error updating characterId:', err);
      res.status(500).json({ message: 'Failed to update character' });
    }
  });

  // Register
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { username, email, password, role, name, subjects } = req.body;

      if (!username || !email || !password || !role) {
        return res
          .status(400)
          .json({ message: 'username, email, password, and role are required' });
      }

      const existingUser = await User.findOne({
        $or: [{ username }, { email }]
      });

      if (existingUser) {
        return res
          .status(409)
          .json({ message: 'Username or email already exists' });
      }

      const user = new User({
        username,
        email,
        role,
        name: name || username,
        subjects: role === 'teacher' && Array.isArray(subjects) && subjects.length > 0
          ? subjects
          : role === 'teacher' ? ['My Subjects'] : undefined,

      });

      await user.setPassword(password);
      const saved = await user.save();

      const token = generateJwt(saved);
      const { passwordHash, ...userSafe } = saved.toObject();

      res.status(201).json({ user: userSafe, token });
    } catch (err) {
      console.error('Error registering user:', err);
      res.status(500).json({ message: 'Failed to register user' });
    }
  });

  // Login
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { usernameOrEmail, password, role } = req.body;

      if (!usernameOrEmail || !password || !role) {
        return res
          .status(400)
          .json({ message: 'username/email, password, and role are required' });
      }

      const user = await User.findOne({
        $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
        role
      });

      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const valid = await user.checkPassword(password);
      if (!valid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = generateJwt(user);
      const { passwordHash, ...userSafe } = user.toObject();

      res.json({ user: userSafe, token });
    } catch (err) {
      console.error('Error logging in:', err);
      res.status(500).json({ message: 'Failed to login' });
    }
  });

  app.get('/api/users', authMiddleware, async (req, res) => {
    try {
      const { role } = req.query;
      const filter = role ? { role } : {};

      const users = await User.find(filter).select('-passwordHash').lean();
      res.json(users);
    } catch (err) {
      console.error('Error fetching users:', err);
      res.status(500).json({ message: 'Failed to fetch users' });
    }
  });

  // ===== Teacher Dashboard Stats =====
  app.get('/api/teachers/:teacherId/dashboard-stats', authMiddleware, async (req, res) => {
    try {
      const { teacherId } = req.params;

      if (req.user.userId !== teacherId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not allowed' });
      }

      // Get teacher courses
      const courses = await Course.find({ teacherId }).select('_id').lean();
      const courseIds = courses.map(c => c._id);

      // Count quests for those courses
      const totalQuests = await Quest.countDocuments({
        courseId: { $in: courseIds }
      });

      res.json({
        totalCourses: courses.length,
        totalQuests
      });
    } catch (err) {
      console.error('Dashboard stats error:', err);
      res.status(500).json({ message: 'Failed to fetch dashboard stats' });
    }
  });


  // ===== ADMIN ROUTES =====

  // ===== ADMIN COURSE MANAGEMENT =====

  // Get all courses for admin review (all statuses)
  app.get('/api/admin/courses', authMiddleware, adminOnly, async (req, res) => {
    try {
      const courses = await Course.find().lean().sort({ createdAt: -1 });
      const formattedCourses = await Promise.all(
        courses.map(async (course) => {
          const teacher = await User.findById(course.teacherId).lean();
          return {
            ...course,
            teacherName: teacher?.name || 'Unknown',
            teacherEmail: teacher?.email || 'N/A'
          };
        })
      );
      res.json(formattedCourses);
    } catch (err) {
      console.error('Error fetching courses for admin:', err);
      res.status(500).json({ message: 'Failed to fetch courses' });
    }
  });

  // Approve a course
  app.put('/api/admin/courses/:courseId/approve', authMiddleware, adminOnly, async (req, res) => {
    try {
      const { courseId } = req.params;
      const updated = await Course.findByIdAndUpdate(
        courseId,
        {
          status: COURSE_STATUS.APPROVED,
          approvedBy: req.user.userId,
          rejectionReason: ''
        },
        { new: true }
      ).lean();
      if (!updated) {
        return res.status(404).json({ message: 'Course not found' });
      }
      res.json({ message: 'Course approved', course: updated });
    } catch (err) {
      console.error('Error approving course:', err);
      res.status(500).json({ message: 'Failed to approve course' });
    }
  });

  // Reject a course
  app.put('/api/admin/courses/:courseId/reject', authMiddleware, adminOnly, async (req, res) => {
    try {
      const { courseId } = req.params;
      const { reason } = req.body;
      if (!reason || !reason.trim()) {
        return res.status(400).json({ message: 'Rejection reason is required' });
      }
      const updated = await Course.findByIdAndUpdate(
        courseId,
        {
          status: COURSE_STATUS.REJECTED,
          rejectionReason: reason.trim(),
          approvedBy: null
        },
        { new: true }
      ).lean();
      if (!updated) {
        return res.status(404).json({ message: 'Course not found' });
      }
      res.json({ message: 'Course rejected', course: updated });
    } catch (err) {
      console.error('Error rejecting course:', err);
      res.status(500).json({ message: 'Failed to reject course' });
    }
  });

  // Delete a course (admin can delete any course)
  app.delete('/api/admin/courses/:courseId', authMiddleware, adminOnly, async (req, res) => {
    try {
      const { courseId } = req.params;

      // ensure course exists
      const course = await Course.findById(courseId).lean();
      if (!course) {
        return res.status(404).json({ message: 'Course not found' });
      }

      // 1) delete quests for this course
      await Quest.deleteMany({ courseId });

      // 2) remove course from students (User.studentClasses is ObjectId[])
      await User.updateMany(
        { studentClasses: courseId },
        { $pull: { studentClasses: courseId } }
      );

      // 3) remove course from student states (StudentState.studentClasses is String[])
      await StudentState.updateMany(
        { studentClasses: String(courseId) },
        { $pull: { studentClasses: String(courseId) } }
      );

      // 4) delete the course
      await Course.deleteOne({ _id: courseId });

      res.json({ message: 'Course deleted', id: courseId });
    } catch (err) {
      console.error('Error deleting course:', err);
      res.status(500).json({ message: 'Failed to delete course' });
    }
  });


  // Get all users (admin only)
  // Optional filter: ?role=student | teacher
  app.get('/api/admin/users', authMiddleware, adminOnly, async (req, res) => {
    try {
      const { role } = req.query;
      const filter = role ? { role } : {};

      const users = await User.find(filter)
        .select('-passwordHash')
        .lean();

      res.json(users);
    } catch (err) {
      console.error('Admin fetch users error:', err);
      res.status(500).json({ message: 'Failed to fetch users' });
    }
  });

  // Create user (admin only)
  app.post('/api/admin/users', authMiddleware, adminOnly, async (req, res) => {
    try {
      const { username, email, password, role, name, subjectName } = req.body;

      if (!username || !email || !password || !role) {
        return res.status(400).json({ message: 'username, email, password, role are required' });
      }

      if (!['student', 'teacher', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role' });
      }

      // prevent public admin creation logic is already here (adminOnly)
      const existing = await User.findOne({ $or: [{ username }, { email }] });
      if (existing) {
        return res.status(409).json({ message: 'Username or email already exists' });
      }

      const user = new User({
        username,
        email,
        role,
        name: name || username,
        subjectName: role === 'teacher' ? (subjectName || 'My Subject') : undefined,

      });

      await user.setPassword(password);
      const saved = await user.save();

      const { passwordHash, ...safe } = saved.toObject();
      res.status(201).json(safe);
    } catch (err) {
      console.error('Admin create user error:', err);
      res.status(500).json({ message: 'Failed to create user' });
    }
  });

  // Update user (admin only)
  app.put('/api/admin/users/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
      console.log('ADMIN UPDATE -> by:', req.user?.username, 'userId:', req.user?.userId, 'targetId:', req.params.id);
      const { id } = req.params;

      // build safe update doc
      const updateDoc = {};

      if (Object.prototype.hasOwnProperty.call(req.body, 'username')) updateDoc.username = req.body.username;
      if (Object.prototype.hasOwnProperty.call(req.body, 'email')) updateDoc.email = req.body.email;
      if (Object.prototype.hasOwnProperty.call(req.body, 'name')) updateDoc.name = req.body.name;

      if (Object.prototype.hasOwnProperty.call(req.body, 'role')) {
        const newRole = req.body.role;
        if (!['student', 'teacher', 'admin'].includes(newRole)) {
          return res.status(400).json({ message: 'Invalid role' });
        }
        updateDoc.role = newRole;

        // teacher fields handling
        if (newRole === 'teacher') {
          updateDoc.subjectName = req.body.subjectName || 'My Subject';
          updateDoc.otpCode = req.body.otpCode || generateTeacherOtp();
        } else {
          updateDoc.subjectName = undefined;
          updateDoc.otpCode = undefined;
        }
      } else {
        // role unchanged; only allow subjectName update if provided
        if (Object.prototype.hasOwnProperty.call(req.body, 'subjectName')) {
          updateDoc.subjectName = req.body.subjectName;
        }
      }

      // optional password reset
      if (Object.prototype.hasOwnProperty.call(req.body, 'password') && req.body.password) {
        const salt = await bcrypt.genSalt(10);
        updateDoc.passwordHash = await bcrypt.hash(req.body.password, salt);
      }

      const updated = await User.findByIdAndUpdate(
        id,
        { $set: updateDoc },
        { new: true }
      ).select('-passwordHash').lean();

      if (!updated) return res.status(404).json({ message: 'User not found' });

      res.json(updated);
    } catch (err) {
      console.error('Admin update user error:', err);
      res.status(500).json({ message: 'Failed to update user' });
    }
  });

  // Delete user (admin only)
  app.delete('/api/admin/users/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
      console.log('ADMIN DELETE -> by:', req.user?.username, 'userId:', req.user?.userId, 'targetId:', req.params.id);
      const { id } = req.params;

      const result = await User.deleteOne({ _id: id });
      if (result.deletedCount === 0) return res.status(404).json({ message: 'User not found' });

      // optional cleanup (recommended)
      try {
        await StudentState.deleteOne({ studentId: id });
        await Character.deleteOne({ ownerUserId: id });
      } catch (cleanupErr) {
        console.warn('Cleanup after user delete failed (ignored):', cleanupErr);
      }

      res.json({ message: 'Deleted' });
    } catch (err) {
      console.error('Admin delete user error:', err);
      res.status(500).json({ message: 'Failed to delete user' });
    }
  });

  app.post('/api/setup-admin', async (req, res) => {
    try {
      const { setupKey, username, email, password } = req.body;

      if (!process.env.SETUP_ADMIN_KEY) {
        return res.status(500).json({ message: 'SETUP_ADMIN_KEY not set on server' });
      }

      if (setupKey !== process.env.SETUP_ADMIN_KEY) {
        return res.status(403).json({ message: 'Invalid setup key' });
      }

      // Only allow if NO admin exists yet
      const existingAdmin = await User.findOne({ role: 'admin' });
      if (existingAdmin) {
        return res.status(409).json({ message: 'Admin already exists' });
      }

      const user = new User({
        username,
        email,
        role: 'admin',
        name: 'System Admin'
      });

      await user.setPassword(password);
      const saved = await user.save();

      const { passwordHash, ...userSafe } = saved.toObject();
      res.status(201).json({ message: 'Admin created', user: userSafe });
    } catch (err) {
      console.error('setup-admin error:', err);
      res.status(500).json({ message: 'Failed to create admin' });
    }
  });

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      backend: 'EduQuest API',
      time: new Date()
    });
  });

  // Get all quests
  app.get('/api/quests', async (req, res) => {
    try {
      const quests = await Quest.find().lean();
      res.json(quests);
    } catch (err) {
      console.error('Error fetching quests:', err);
      res.status(500).json({ message: 'Failed to fetch quests' });
    }
  });

  // Get a single quest by id
  app.get('/api/quests/:id', async (req, res) => {
    try {
      const quest = await Quest.findOne({ id: req.params.id }).lean();
      if (!quest) {
        return res.status(404).json({ message: 'Quest not found' });
      }
      res.json(quest);
    } catch (err) {
      console.error('Error fetching quest:', err);
      res.status(500).json({ message: 'Failed to fetch quest' });
    }
  });

  // Create a new quest
  app.post('/api/quests', authMiddleware, async (req, res) => {
    try {
      if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Only teachers can create quests' });
      }
      const body = req.body;

      if (!body.title || !body.description) {
        return res
          .status(400)
          .json({ message: 'title and description are required' });
      }

      // generate an id if not provided
      const questId = body.id || `quest_${Date.now()}`;

      const newQuest = new Quest({
        id: questId,
        title: body.title,
        description: body.description,
        difficulty: body.difficulty || 'Easy',
        courseId: body.courseId,
        courseName: body.courseName,
        section: body.section,
        xpReward: body.xpReward || 0,
        timeLimit: body.timeLimit ?? null,
        teacherId: req.user.userId,
        questions: body.questions || []
      });

      const savedQuest = await newQuest.save();
      res.status(201).json(savedQuest);
    } catch (err) {
      console.error('Error creating quest:', err);
      res.status(500).json({ message: 'Failed to create quest' });
    }
  });

  // Update an existing quest
  app.put('/api/quests/:id', authMiddleware, async (req, res) => {
    try {
      if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Only teachers can update quests' });
      }
      const questId = req.params.id;
      const updates = req.body;

      const updatedQuest = await Quest.findOneAndUpdate(
        { id: questId },
        updates,
        { new: true } // return updated doc
      ).lean();

      if (!updatedQuest) {
        return res.status(404).json({ message: 'Quest not found' });
      }

      res.json(updatedQuest);
    } catch (err) {
      console.error('Error updating quest:', err);
      res.status(500).json({ message: 'Failed to update quest' });
    }
  });

  // Delete a quest
  app.delete('/api/quests/:id', authMiddleware, async (req, res) => {
    try {
      if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: 'Only teachers can delete quests' });
      }
      const questId = req.params.id;

      const result = await Quest.deleteOne({ id: questId });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: 'Quest not found' });
      }

      res.json({ message: 'Quest deleted', id: questId });
    } catch (err) {
      console.error('Error deleting quest:', err);
      res.status(500).json({ message: 'Failed to delete quest' });
    }
  });

  app.get('/api/students/:studentId/state', async (req, res) => {
    try {
      const { studentId } = req.params;

      let state = await StudentState.findOne({ studentId }).lean();

      // auto-create if not exists
      if (!state) {
        const created = await StudentState.create({ studentId });
        state = created.toObject();
      }

      res.json({
        ...state,
        studentClasses: state.studentClasses || [] // Add studentClasses to the response
      });
    } catch (err) {
      console.error('Error fetching student state:', err);
      res.status(500).json({ message: 'Failed to fetch student state' });
    }
  });



  app.put('/api/students/:studentId/state', async (req, res) => {
    try {
      const { studentId } = req.params;
      const updateDoc = {};

      const dedupeStringArray = (value) => {
        if (!Array.isArray(value)) return [];
        const normalized = value.map((v) => String(v));
        return Array.from(new Set(normalized));
      };

      if ('character' in req.body) updateDoc.character = req.body.character;
      if ('achievements' in req.body) updateDoc.achievements = req.body.achievements;
      if ('inventory' in req.body) updateDoc.inventory = req.body.inventory;
      if ('progress' in req.body) updateDoc.progress = req.body.progress;
      if ('studentClasses' in req.body) {
        updateDoc.studentClasses = dedupeStringArray(req.body.studentClasses);
      }
      if ('level' in req.body && typeof req.body.level === 'number') updateDoc.level = req.body.level;
      if ('xp' in req.body && typeof req.body.xp === 'number') updateDoc.xp = req.body.xp;

      const state = await StudentState.findOneAndUpdate(
        { studentId },
        { $set: updateDoc },
        { new: true, upsert: true }
      ).lean();

      res.json(state);
    } catch (err) {
      console.error('Error saving student state:', err);
      res.status(500).json({ message: 'Failed to save student state' });
    }
  }); // <-- This closes the endpoint!



  // Update progress for a quest and adjust level/xp
  app.post('/api/students/:studentId/progress', async (req, res) => {
    try {
      const { studentId } = req.params;
      const { questId, score, xpGained } = req.body;

      if (!questId || typeof score !== 'number') {
        return res
          .status(400)
          .json({ message: 'questId and numeric score are required' });
      }

      let state = await StudentState.findOne({ studentId });

      if (!state) {
        state = new StudentState({ studentId });
      }

      // update progress map
      state.progress.set(questId, score);

      // update xp / level
      const gained = typeof xpGained === 'number' ? xpGained : score * 10;
      state.xp += gained;

      const xpForNextLevel = state.level * 100;
      while (state.xp >= xpForNextLevel) {
        state.xp -= xpForNextLevel;
        state.level += 1;
      }

      await state.save();
      res.json(state);
    } catch (err) {
      console.error('Error updating student progress:', err);
      res.status(500).json({ message: 'Failed to update progress' });
    }
  });



  app.post('/api/students/:studentId/remove-course', async (req, res) => {
    const { studentId } = req.params;
    const { courseId } = req.body;

    // Remove from User
    const student = await User.findById(studentId);
    if (!student) return res.status(404).json({ message: 'Student not found' });
    student.studentClasses = (student.studentClasses || []).filter(
      cid => String(cid) !== String(courseId)
    );
    await student.save();

    // Remove from StudentState
    const state = await StudentState.findOne({ studentId });
    if (state) {
      state.studentClasses = (state.studentClasses || []).filter(
        cid => String(cid) !== String(courseId)
      );
      await state.save();
    }

    const updatedState = await StudentState.findOne({ studentId }).lean();
    res.json({ success: true, updatedState });
  });

  app.post('/api/students/:studentId/add-course', async (req, res) => {
    try {
      const { studentId } = req.params;
      const { courseId } = req.body;

      if (!courseId) return res.status(400).json({ message: 'courseId is required' });

      // ✅ Check if course is approved
      const course = await Course.findById(courseId).lean();
      if (!course) return res.status(404).json({ message: 'Course not found' });
      if (course.status !== COURSE_STATUS.APPROVED) {
        return res.status(403).json({ message: 'Course is not approved. Students cannot enroll.' });
      }

      const student = await User.findById(studentId).lean();
      if (!student) return res.status(404).json({ message: 'Student not found' });

      const inUser = (student.studentClasses || []).some(cid => String(cid) === String(courseId));

      const state = await StudentState.findOne({ studentId }).lean();
      const inState = (state?.studentClasses || []).some(cid => String(cid) === String(courseId));

      if (inUser || inState) {
        return res.status(409).json({ message: 'Student already enrolled' });
      }

      await User.updateOne(
        { _id: studentId },
        { $addToSet: { studentClasses: courseId } }
      );

      await StudentState.updateOne(
        { studentId },
        { $addToSet: { studentClasses: String(courseId) } },
        { upsert: true }
      );

      const updatedState = await StudentState.findOne({ studentId }).lean();
      return res.json({ success: true, updatedState });
    } catch (err) {
      console.error('add-course error:', err);
      res.status(500).json({ message: 'Failed to add course' });
    }
  });







  // ===== START SERVER =====
  const PORT = process.env.PORT || 5000;

  app.listen(PORT, () => {
    console.log(`EduQuest backend running on http://localhost:${PORT}`);
  });
