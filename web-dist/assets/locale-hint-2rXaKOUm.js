(function(){try{
var f={"en":"locale-en-C2f2P078.js","zh-CN":"locale-zh-CN-Bqbc2bWk.js","zh-TW":"locale-zh-TW-BqCOYfH7.js","ja":"locale-ja-Cw89ceNn.js","ko":"locale-ko-C14JhLNU.js","es":"locale-es-YXyfKo72.js","fr":"locale-fr-CiygbbnJ.js","de":"locale-de-CzF7XBH0.js","ru":"locale-ru-Ct-NEiEF.js","pt-BR":"locale-pt-BR-Cn2ypYYw.js"},m=[["en",["en"]],["zh-CN",["zh-cn","zh-sg","zh-hans","zh"]],["zh-TW",["zh-tw","zh-hk","zh-mo","zh-hant"]],["ja",["ja"]],["ko",["ko"]],["es",["es"]],["fr",["fr"]],["de",["de"]],["ru",["ru"]],["pt-BR",["pt"]]],c=null,s=null,p,i,j,k,l,h;
var u=document.currentScript.src;
try{s=localStorage.getItem("gately.locale")}catch(e){}
if(s&&f[s]){c=s}
if(!c){p=navigator.languages&&navigator.languages.length?navigator.languages:[navigator.language];
for(i=0;i<p.length&&!c;i++){l=String(p[i]).toLowerCase();
for(j=0;j<m.length&&!c;j++){for(k=0;k<m[j][1].length;k++){h=m[j][1][k];if(l===h||l.indexOf(h+"-")===0){c=m[j][0];break}}}}}
c=c||"en";
if(!f[c]){return}
l=document.createElement("link");l.rel="modulepreload";l.crossOrigin="";l.href=u.slice(0,u.lastIndexOf("/")+1)+f[c];
document.head.appendChild(l)
}catch(e){}})();
