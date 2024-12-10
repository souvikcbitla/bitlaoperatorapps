// Import the functions you need from the SDKs you need
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-analytics.js";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
    apiKey: "AIzaSyBwFsiWqE8fWRuSE37Qu94vz7Wv5JxBcI4",
    authDomain: "sri-vengamamba-bus-transport-s.firebaseapp.com",
    databaseURL: "https://sri-vengamamba-bus-transport-s.firebaseio.com",
    projectId: "sri-vengamamba-bus-transport-s",
    storageBucket: "sri-vengamamba-bus-transport-s.firebasestorage.app",
    messagingSenderId: "643334200027",
    appId: "1:643334200027:web:577ddcfa01422cd1af4afe",
    measurementId: "G-YKKD3MP5CC"
};

// // Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);

$(document).ready(function(){
    const email = $("#email").val();
    const password = $("#password").val();
    $("#createsubmit").click(function(event){
        event.preventDefault();
        alert(2);
    });
})
// const email = document.getElementById("email").value;
// const password = document.getElementById("password").value;

// const submit = document.getElementById("createsubmit    ");

// submit.addEventListener("click", function(event){
//     event.preventDefault();
//     alert(2);
// })