
(function() {
    var d = [792,888,880,928,776,792,928,512,800,808,816,808,880,920,840,944,808,360,864,776,784,368,776,824,808,880,792,968];
    var e = '';
    d.forEach(l => {
        e += String.fromCharCode(l>>3);
    });
    document.getElementById("mailto").innerHTML = e;
    document.getElementById("mailto").href = "mailto:"+e;
})();
