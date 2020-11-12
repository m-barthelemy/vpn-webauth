let searchParams = new URLSearchParams(window.location.search);
if (searchParams.has('error')) {
    $("#error").show();
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