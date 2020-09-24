'use strict';

document.addEventListener('DOMContentLoaded', function () {
  var $navbarBurgers = Array.prototype.slice.call(document.querySelectorAll('.navbar-burger'), 0);

  if ($navbarBurgers.length > 0) {
    $navbarBurgers.forEach(function (el) {
      el.addEventListener('click', function () {
        var target = el.dataset.target;
        var $target = document.getElementById(target);
        el.classList.toggle('is-active');
        $target.classList.toggle('is-active');
      });
    });
  }

  var handleSolutions = function handleSolutions() {
    if (window.location.href.endsWith("#products")) {
      $(".service").each(function (index) {
        $(this).removeClass("has-background-info-light");
        $(this).addClass("transparent-50");
      });
      $(".product").each(function (index) {
        $(this).removeClass("transparent-50");
        $(this).addClass("has-background-info-light");
      });
    } else if (window.location.href.endsWith("#services")) {
      $(".product").each(function (index) {
        $(this).removeClass("has-background-info-light");
        $(this).addClass("transparent-50");
      });
      $(".service").each(function (index) {
        $(this).removeClass("transparent-50");
        $(this).addClass("has-background-info-light");
      });
    } else {
      $(".product").each(function (index) {
        $(this).removeClass("has-background-info-light");
        $(this).removeClass("transparent-50");
      });
      $(".service").each(function (index) {
        $(this).removeClass("has-background-info-light");
        $(this).removeClass("transparent-50");
      });
    }
  };

  handleSolutions();
  window.onhashchange = handleSolutions;
});