const nav = document.getElementById("site-nav");
const toggle = document.querySelector(".nav-toggle");
const form = document.getElementById("scan-form");
const status = document.getElementById("form-status");

function setNavOpen(open) {
  nav.classList.toggle("is-open", open);
  toggle.setAttribute("aria-expanded", String(open));
}

toggle.addEventListener("click", () => {
  setNavOpen(!nav.classList.contains("is-open"));
});

nav.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => setNavOpen(false));
});

function showStatus(message, type) {
  status.hidden = false;
  status.textContent = message;
  status.classList.toggle("is-error", type === "error");
  status.classList.toggle("is-success", type === "success");
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const fields = [...form.querySelectorAll("[required]")];
  let valid = true;

  fields.forEach((field) => {
    const wrap = field.closest(".field");
    const empty = !field.value.trim();
    wrap.classList.toggle("invalid", empty);
    if (empty) valid = false;
  });

  const email = form.elements.email.value.trim();
  if (email && !/^[\^\s@]+@[\^\s@]+\.[\^\s@]+$/.test(email)) {
    form.elements.email.closest(".field").classList.add("invalid");
    valid = false;
  }

  if (!valid) {
    showStatus("Please complete the required fields.", "error");
    return;
  }

  form.reset();
  fields.forEach((field) => field.closest(".field").classList.remove("invalid"));
  showStatus(
    "Thank you. Your request is recorded on this page. Add a destination email when you are ready to receive enquiries.",
    "success"
  );
});
