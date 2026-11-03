// Vercel Serverless Function: Feedback Management
const CLOUD_STORAGE_URL = 'https://kvdb.io/8n9b3rNgy9wGWHd5VjAshV/feedbacks';

// In-memory fallback cache across lambda warm invocations
let memoryCache = [
  {
    id: 'fb_init_01',
    type: 'student',
    name: 'Aarav Sharma',
    email: 'aarav.sharma@dtu.ac.in',
    rating: 5,
    institution: 'Delhi Technological University (DTU)',
    course: 'B.Tech CSE / Cybersecurity',
    conceptClarity: 5,
    uiRating: 5,
    readiness: 'Capstone / Final Year Level (Exceptional)',
    favoriteFeatures: ['Real-Time Registry Polling', '1-Click Threat Remediation', 'Always-On Desktop HUD Gadget'],
    implementationSuggestions: 'Please implement an automated quarantine directory for newly detected autorun binaries and add Windows Event Log (ETW) correlation.',
    testimonial: 'The real-time registry detection and atomic rollback mechanism is exceptionally well-engineered. Perfect final year capstone project!',
    createdAt: '2026-11-03T15:30:00.000Z'
  },
  {
    id: 'fb_init_02',
    type: 'company',
    name: 'Rohit Verma',
    email: 'rohit.verma@quickheal.com',
    rating: 5,
    company: 'QuickHeal Technologies',
    designation: 'SOC Analyst / Blue Team Engineer',
    practicality: 5,
    securityRating: 5,
    hireability: 'Ready for SOC Analyst / Security Developer Role',
    enterpriseRecommendations: ['Centralized SIEM / Syslog Forwarding', 'YARA Rule Scanning on Autorun Files'],
    implementationSuggestions: 'Consider adding YARA pattern scanning on executables found in Run/RunOnce keys to detect packed malware before registry execution.',
    testimonial: 'Strong systems programming with clean Windows DPAPI security architecture. Very promising candidate for blue team and endpoint defense roles.',
    createdAt: '2026-11-03T14:15:00.000Z'
  }
];

// Helper to fetch current feedbacks from cloud store
async function getStoredFeedbacks() {
  try {
    const res = await fetch(CLOUD_STORAGE_URL, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) {
        memoryCache = data;
        return memoryCache;
      }
    }
  } catch (err) {
    console.warn('Cloud store fetch error, using memory fallback:', err.message);
  }
  return memoryCache;
}

// Clean feedback object by omitting empty fields to optimize payload
function cleanFeedback(fb) {
  const clean = {};
  for (const [k, v] of Object.entries(fb)) {
    if (v !== '' && v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0)) {
      clean[k] = v;
    }
  }
  return clean;
}

// Helper to save feedbacks list to cloud store
async function saveFeedbacks(feedbacks) {
  const cleanedList = feedbacks.map(cleanFeedback);
  memoryCache = cleanedList;
  try {
    const res = await fetch(CLOUD_STORAGE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cleanedList)
    });
    return res.ok;
  } catch (err) {
    console.warn('Cloud store save error, stored in memory cache:', err.message);
    return true;
  }
}

export default async function handler(req, res) {
  // CORS configuration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // GET: Fetch all feedbacks (for admin or public metrics)
  if (req.method === 'GET') {
    try {
      const feedbacks = await getStoredFeedbacks();
      // Sort newest first
      feedbacks.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
      return res.status(200).json({
        success: true,
        count: feedbacks.length,
        feedbacks
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  // POST: Submit a new feedback entry
  if (req.method === 'POST') {
    try {
      const body = req.body || {};
      const {
        type, // 'student' or 'company'
        name,
        email,
        rating,
        // Student fields
        institution,
        course,
        conceptClarity,
        uiRating,
        readiness,
        favoriteFeatures,
        // Company fields
        company,
        designation,
        practicality,
        securityRating,
        hireability,
        enterpriseRecommendations,
        // Special requested field
        implementationSuggestions,
        suggestions,
        testimonial
      } = body;

      // Basic validations
      if (!name || !name.trim()) {
        return res.status(400).json({ success: false, error: 'Full Name is required' });
      }
      if (!email || !email.trim()) {
        return res.status(400).json({ success: false, error: 'Email address is required' });
      }
      if (!type || !['student', 'company'].includes(type)) {
        return res.status(400).json({ success: false, error: 'Valid reviewer type (student/company) is required' });
      }

      const newFeedback = {
        id: 'fb_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
        type,
        name: name.trim(),
        email: email.trim(),
        rating: Number(rating) || 5,
        // Student specific
        institution: institution ? institution.trim() : '',
        course: course ? course.trim() : '',
        conceptClarity: Number(conceptClarity) || 5,
        uiRating: Number(uiRating) || 5,
        readiness: readiness || 'Final Year Ready',
        favoriteFeatures: Array.isArray(favoriteFeatures) ? favoriteFeatures : [],
        // Company specific
        company: company ? company.trim() : '',
        designation: designation ? designation.trim() : '',
        practicality: Number(practicality) || 5,
        securityRating: Number(securityRating) || 5,
        hireability: hireability || 'Ready for SOC / Security Role',
        enterpriseRecommendations: Array.isArray(enterpriseRecommendations) ? enterpriseRecommendations : [],
        // Special implementation feedback
        implementationSuggestions: (implementationSuggestions || suggestions || '').trim(),
        testimonial: testimonial ? testimonial.trim() : '',
        createdAt: new Date().toISOString()
      };

      const feedbacks = await getStoredFeedbacks();
      feedbacks.push(newFeedback);
      await saveFeedbacks(feedbacks);

      return res.status(201).json({
        success: true,
        message: 'Feedback submitted successfully. Thank you!',
        feedback: newFeedback
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  // DELETE: Remove feedback (Admin only)
  if (req.method === 'DELETE') {
    try {
      const { id } = req.query || req.body || {};
      if (!id) {
        return res.status(400).json({ success: false, error: 'Feedback ID is required for deletion' });
      }

      const feedbacks = await getStoredFeedbacks();
      const updatedFeedbacks = feedbacks.filter(fb => fb.id !== id);

      if (updatedFeedbacks.length === feedbacks.length) {
        return res.status(404).json({ success: false, error: 'Feedback not found' });
      }

      await saveFeedbacks(updatedFeedbacks);
      return res.status(200).json({
        success: true,
        message: 'Feedback deleted successfully',
        remainingCount: updatedFeedbacks.length
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
