const logoutBtn = document.getElementById("logoutBtn");

logoutBtn.addEventListener("click", (e) => {
  e.preventDefault();
  fetch("/api/sessions/logout").then((response) => {
    if (response.status === 200) {
      window.location.replace("/login");
    }
  });
});
