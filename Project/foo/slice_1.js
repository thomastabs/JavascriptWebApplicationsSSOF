var pos = document.URL.indexOf("name=");
var name = document.URL.substring(pos + 5);
document.write(name);