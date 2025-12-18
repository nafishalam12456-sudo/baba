document.addEventListener("DOMContentLoaded", () => {
    var text = document.getElementById('success-msg').innerText;
    if(text === null || text === ' ' || text === undefined || text === ''){
        $("#search-form").show();  
    }
    else if(text === 'Aah! Wrong uid entered'){
        $("#search-form").hide(); 
        

    }
    else{
        $("#search-form").hide(); 
        //congratulations code---------------------------------------------
       
        //confetti code---------------------------------------------------- 
        var end = Date.now() + (3 * 1000);
        var colors = ['#aff00f', '#00d7ff'];

        (function frame() {
        confetti({
            particleCount: 2,
            angle: 60,
            spread: 55,
            origin: { x: 0 },
            colors: colors
        });
        confetti({
            particleCount: 2,
            angle: 120,
            spread: 55,
            origin: { x: 1 },
            colors: colors
        });

        if (Date.now() < end) {
            requestAnimationFrame(frame);
        }
        }());
    }
});