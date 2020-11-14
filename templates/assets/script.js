let searchParams = new URLSearchParams(window.location.search);
if (searchParams.has('error')) {
    $("#error").show();
}
if (searchParams.has('options')) {
    var allOptions = searchParams.get('options').split(",");
    if (!allOptions.includes("touchid")) {
        $("#touchid").hide();
    }
}
$("input[type='number']").keyup( function() {
    console.warn("change! " + $("input[type='number']").val());
    var dataLength = $(this).val().length;
    
    if(dataLength > 0) {
        $("#error").hide();
    }
    if (dataLength == 6) {
        $("form").submit();
    }
}).change();