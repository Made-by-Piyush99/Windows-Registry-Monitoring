// Feedback Form Application Logic
let currentRole = 'student';

// Star Rating Descriptions
const starLabels = {
  overall: {
    1: '1.0 / 5.0 (Needs Severe Improvement)',
    2: '2.0 / 5.0 (Below Average)',
    3: '3.0 / 5.0 (Average)',
    4: '4.0 / 5.0 (Very Good)',
    5: '5.0 / 5.0 (Exceptional)'
  },
  concept: {
    1: '1.0 / 5.0 (Unclear)',
    2: '2.0 / 5.0 (Slightly Confusing)',
    3: '3.0 / 5.0 (Understood Basics)',
    4: '4.0 / 5.0 (Very Clear)',
    5: '5.0 / 5.0 (Very Clear & Educational)'
  },
  ui: {
    1: '1.0 / 5.0 (Basic)',
    2: '2.0 / 5.0 (Needs Styling)',
    3: '3.0 / 5.0 (Decent)',
    4: '4.0 / 5.0 (Modern)',
    5: '5.0 / 5.0 (High SOC Polish)'
  },
  practicality: {
    1: '1.0 / 5.0 (Theoretical Only)',
    2: '2.0 / 5.0 (Limited Use)',
    3: '3.0 / 5.0 (Practical in Test Environments)',
    4: '4.0 / 5.0 (Strong Blue Team Value)',
    5: '5.0 / 5.0 (High Endpoint Utility)'
  },
  security: {
    1: '1.0 / 5.0 (Basic)',
    2: '2.0 / 5.0 (Standard)',
    3: '3.0 / 5.0 (Good)',
    4: '4.0 / 5.0 (Robust Defensive Architecture)',
    5: '5.0 / 5.0 (Enterprise Standards)'
  }
};

// Switch active role tab
function setRole(role) {
  currentRole = role;
  const tabStudent = document.getElementById('tab-student');
  const tabCompany = document.getElementById('tab-company');
  const studentSection = document.getElementById('student-section');
  const companySection = document.getElementById('company-section');

  if (role === 'student') {
    tabStudent.classList.add('active');
    tabCompany.classList.remove('active');
    studentSection.style.display = 'block';
    companySection.style.display = 'none';
  } else {
    tabCompany.classList.add('active', 'company-tab');
    tabStudent.classList.remove('active');
    studentSection.style.display = 'none';
    companySection.style.display = 'block';
  }
}

// Setup Interactive Star Rating Widgets
function setupStarRatings() {
  const ratingWidgets = [
    { id: 'rating-overall', type: 'overall', textId: 'rating-overall-text' },
    { id: 'rating-concept', type: 'concept', textId: 'rating-concept-text' },
    { id: 'rating-ui', type: 'ui', textId: 'rating-ui-text' },
    { id: 'rating-practicality', type: 'practicality', textId: 'rating-practicality-text' },
    { id: 'rating-security', type: 'security', textId: 'rating-security-text' }
  ];

  ratingWidgets.forEach(widget => {
    const container = document.getElementById(widget.id);
    const descText = document.getElementById(widget.textId);
    if (!container) return;

    const stars = container.querySelectorAll('.star');

    stars.forEach(star => {
      // Hover effect
      star.addEventListener('mouseenter', () => {
        const val = parseInt(star.getAttribute('data-value'), 10);
        stars.forEach(s => {
          const sVal = parseInt(s.getAttribute('data-value'), 10);
          if (sVal <= val) {
            s.classList.add('hover');
          } else {
            s.classList.remove('hover');
          }
        });
      });

      // Mouse leave
      container.addEventListener('mouseleave', () => {
        stars.forEach(s => s.classList.remove('hover'));
      });

      // Click to set
      star.addEventListener('click', () => {
        const val = parseInt(star.getAttribute('data-value'), 10);
        container.setAttribute('data-rating', val);
        stars.forEach(s => {
          const sVal = parseInt(s.getAttribute('data-value'), 10);
          if (sVal <= val) {
            s.classList.add('active');
          } else {
            s.classList.remove('active');
          }
        });
        if (descText && starLabels[widget.type]) {
          descText.textContent = starLabels[widget.type][val] || `${val}.0 / 5.0`;
        }
      });
    });
  });
}

// Show Toast Notification
function showToast(message, isError = false) {
  const toast = document.getElementById('toast');
  const toastText = document.getElementById('toast-text');
  const toastIcon = document.getElementById('toast-icon');

  toastText.textContent = message;
  toastIcon.textContent = isError ? '⚠' : '✓';
  if (isError) {
    toast.classList.add('error');
  } else {
    toast.classList.remove('error');
  }

  toast.classList.add('show');
  setTimeout(() => {
    toast.classList.remove('show');
  }, 4000);
}

// Modal controls
function showModal() {
  document.getElementById('success-modal').classList.add('active');
}

function closeModal() {
  document.getElementById('success-modal').classList.remove('active');
  document.getElementById('feedback-form').reset();
  setRole('student');
}

// Handle Form Submission
async function handleSubmit(e) {
  e.preventDefault();

  const btnSubmit = document.getElementById('btn-submit');
  const name = document.getElementById('input-name').value.trim();
  const email = document.getElementById('input-email').value.trim();
  const overallRating = parseInt(document.getElementById('rating-overall').getAttribute('data-rating') || '5', 10);
  const implementationSuggestions = document.getElementById('input-implementation').value.trim();
  const testimonial = document.getElementById('input-testimonial').value.trim();

  if (!name || !email) {
    showToast('Please provide your name and email.', true);
    return;
  }

  const payload = {
    type: currentRole,
    name,
    email,
    rating: overallRating,
    implementationSuggestions,
    testimonial
  };

  if (currentRole === 'student') {
    const institution = document.getElementById('input-institution').value.trim();
    if (!institution) {
      showToast('Please enter your College or Institute name.', true);
      document.getElementById('input-institution').focus();
      return;
    }
    payload.institution = institution;
    payload.course = document.getElementById('input-course').value.trim();
    payload.conceptClarity = parseInt(document.getElementById('rating-concept').getAttribute('data-rating') || '5', 10);
    payload.uiRating = parseInt(document.getElementById('rating-ui').getAttribute('data-rating') || '5', 10);

    const readinessRadio = document.querySelector('input[name="readiness"]:checked');
    payload.readiness = readinessRadio ? readinessRadio.value : 'Capstone / Final Year Level';

    const favFeatures = [];
    document.querySelectorAll('input[name="student_fav"]:checked').forEach(cb => favFeatures.push(cb.value));
    payload.favoriteFeatures = favFeatures;

  } else {
    const company = document.getElementById('input-company').value.trim();
    if (!company) {
      showToast('Please enter your Company or Organization name.', true);
      document.getElementById('input-company').focus();
      return;
    }
    payload.company = company;
    payload.designation = document.getElementById('input-designation').value;
    payload.practicality = parseInt(document.getElementById('rating-practicality').getAttribute('data-rating') || '5', 10);
    payload.securityRating = parseInt(document.getElementById('rating-security').getAttribute('data-rating') || '5', 10);

    const hireabilityRadio = document.querySelector('input[name="hireability"]:checked');
    payload.hireability = hireabilityRadio ? hireabilityRadio.value : 'Ready for SOC Role';

    const enterpriseRecs = [];
    document.querySelectorAll('input[name="company_rec"]:checked').forEach(cb => enterpriseRecs.push(cb.value));
    payload.enterpriseRecommendations = enterpriseRecs;
  }

  // Button Loading State
  btnSubmit.disabled = true;
  btnSubmit.innerHTML = '<span>⏳ Transmitting Feedback...</span>';

  try {
    const res = await fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (res.ok && data.success) {
      showModal();
      showToast('Feedback successfully submitted!');
    } else {
      showToast(data.error || 'Failed to submit feedback. Please try again.', true);
    }
  } catch (err) {
    console.error('Submission error:', err);
    showToast('Network error while submitting. Please check connection.', true);
  } finally {
    btnSubmit.disabled = false;
    btnSubmit.innerHTML = '<span>🚀 Submit Feedback &amp; Review</span>';
  }
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  setupStarRatings();
});
