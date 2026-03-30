export function generateAnimatedFractalHTML(
  seed: number,
  cx: number,
  cy: number,
  zoom: number,
  maxIter: number
): string {
  return `<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<style>*{margin:0;padding:0;overflow:hidden}body{background:#000}canvas{display:block}</style>
</head><body>
<canvas id="c"></canvas>
<script>
(function(){
var SEED=${seed|0};
var CX=${cx};
var CY=${cy};
var ZOOM=${Math.max(zoom,0.1)};
var MAX_ITER=${Math.max(maxIter,50)};

var canvas=document.getElementById('c');
var ctx=canvas.getContext('2d');
var W,H,imgData,buf;
var t=0;

function seededRandom(n){
  var x=Math.sin(SEED+n)*10000;
  return x-Math.floor(x);
}

var driftSpeed=0.00015+((SEED%1000)*0.00000005);
var hueBase=(SEED%360);

var PARTICLE_COUNT=60;
var particles=[];
for(var i=0;i<PARTICLE_COUNT;i++){
  particles.push({
    angle:seededRandom(i)*Math.PI*2,
    radius:0.92+seededRandom(i+99)*0.05,
    speed:0.0004+seededRandom(i+199)*0.0004,
    size:1+seededRandom(i+299)*1.5,
    opacity:0.15+seededRandom(i+399)*0.25
  });
}

var activeParticles=PARTICLE_COUNT;
var renderEveryNth=1;
var frameCount=0;
var driftEnabled=true;

var fpsHistory=[];
var lastFrameTime=performance.now();
var fpsCheckTimer=0;
var LOW_FPS_45_START=0;
var LOW_FPS_30_START=0;

function resize(){
  var s=Math.min(window.innerWidth,window.innerHeight);
  W=H=s;
  canvas.width=W;
  canvas.height=H;
  imgData=ctx.createImageData(W,H);
  buf=imgData.data;
}
resize();
window.addEventListener('resize',resize);

function hslToRgb(h,s,l){
  h=((h%360)+360)%360;
  var c=(1-Math.abs(2*l-1))*s;
  var x=c*(1-Math.abs((h/60)%2-1));
  var m=l-c/2;
  var r=0,g=0,b=0;
  if(h<60){r=c;g=x}
  else if(h<120){r=x;g=c}
  else if(h<180){g=c;b=x}
  else if(h<240){g=x;b=c}
  else if(h<300){r=x;b=c}
  else{r=c;b=x}
  return[(r+m)*255|0,(g+m)*255|0,(b+m)*255|0];
}

function renderFractal(){
  var zoomAnimated=driftEnabled?ZOOM*(1+Math.sin(t*driftSpeed)*0.015):ZOOM;
  var oxAnimated=driftEnabled?Math.cos(t*driftSpeed*0.6)*0.003:0;
  var oyAnimated=driftEnabled?Math.sin(t*driftSpeed*0.8)*0.003:0;

  var acx=CX+oxAnimated;
  var acy=CY+oyAnimated;

  var viewSize=4.0/Math.pow(zoomAnimated,0.15);
  var step=viewSize/W;
  var startX=acx-viewSize/2;
  var startY=acy-viewSize/2;

  var hueShift=(t*10+hueBase)%360;

  var radius=W/2;
  var cx2=W/2;
  var cy2=H/2;
  var r2=radius*radius;

  for(var py=0;py<H;py++){
    var ci=startY+py*step;
    var dy=py-cy2;
    for(var px=0;px<W;px++){
      var idx=(py*W+px)*4;
      var dx=px-cx2;
      if(dx*dx+dy*dy>r2){
        buf[idx]=0;buf[idx+1]=0;buf[idx+2]=0;buf[idx+3]=255;
        continue;
      }
      var cr=startX+px*step;
      var zr=0,zi=0,iter=0;
      while(iter<MAX_ITER){
        var zr2=zr*zr;
        var zi2=zi*zi;
        if(zr2+zi2>4)break;
        zi=2*zr*zi+ci;
        zr=zr2-zi2+cr;
        iter++;
      }
      if(iter>=MAX_ITER){
        buf[idx]=10;buf[idx+1]=10;buf[idx+2]=10;buf[idx+3]=255;
      }else{
        var norm=iter/MAX_ITER;
        var distFromEdge=Math.sqrt(dx*dx+dy*dy)/radius;
        var isEdgeRegion=distFromEdge>0.75;

        if(isEdgeRegion&&norm>0.01){
          var hue=(hueShift+norm*180)%360;
          var rgb=hslToRgb(hue,0.85,0.35+norm*0.25);
          buf[idx]=rgb[0];buf[idx+1]=rgb[1];buf[idx+2]=rgb[2];buf[idx+3]=255;
        }else{
          var intensity=Math.pow(norm,0.22);
          var r,g,b;
          if((iter|0)%6===0){
            r=220+intensity*35|0;
            g=60+intensity*80|0;
            b=255;
          }else{
            r=intensity*40|0;
            g=180+intensity*75|0;
            b=255;
          }
          buf[idx]=r;buf[idx+1]=g;buf[idx+2]=b;buf[idx+3]=255;
        }
      }
    }
  }
  ctx.putImageData(imgData,0,0);
}

function renderParticles(){
  var radius=W/2;
  var cx2=W/2;
  var cy2=H/2;
  ctx.save();
  ctx.globalCompositeOperation='lighter';
  for(var i=0;i<activeParticles;i++){
    var p=particles[i];
    p.angle+=p.speed;
    var px=cx2+Math.cos(p.angle)*p.radius*radius;
    var py=cy2+Math.sin(p.angle)*p.radius*radius;
    var dx=px-cx2;
    var dy=py-cy2;
    if(dx*dx+dy*dy>(radius*radius))continue;
    ctx.beginPath();
    ctx.arc(px,py,p.size,0,Math.PI*2);
    ctx.fillStyle='rgba(0,255,170,'+p.opacity+')';
    ctx.shadowColor='rgba(0,255,170,0.6)';
    ctx.shadowBlur=4;
    ctx.fill();
  }
  ctx.restore();
}

function renderGlow(){
  var radius=W/2;
  var cx2=W/2;
  var cy2=H/2;

  ctx.save();
  var grad=ctx.createRadialGradient(cx2,cy2,radius*0.6,cx2,cy2,radius);
  grad.addColorStop(0,'rgba(0,255,170,0)');
  grad.addColorStop(1,'rgba(0,255,170,0.08)');
  ctx.fillStyle=grad;
  ctx.beginPath();
  ctx.arc(cx2,cy2,radius,0,Math.PI*2);
  ctx.fill();
  ctx.restore();

  ctx.save();
  ctx.globalCompositeOperation='lighter';
  ctx.filter='blur(8px)';
  ctx.globalAlpha=0.06;
  ctx.drawImage(canvas,0,0);
  ctx.globalAlpha=1;
  ctx.filter='none';
  ctx.globalCompositeOperation='source-over';
  ctx.restore();
}

function checkPerformance(){
  var now=performance.now();
  var dt=now-lastFrameTime;
  lastFrameTime=now;
  var fps=dt>0?1000/dt:60;
  fpsHistory.push(fps);
  if(fpsHistory.length>30)fpsHistory.shift();

  fpsCheckTimer+=dt;
  if(fpsCheckTimer>2000){
    fpsCheckTimer=0;
    var avg=0;
    for(var i=0;i<fpsHistory.length;i++)avg+=fpsHistory[i];
    avg/=fpsHistory.length;

    if(avg<30){
      driftEnabled=false;
      renderEveryNth=2;
      activeParticles=Math.max(20,PARTICLE_COUNT*0.5|0);
    }else if(avg<45){
      activeParticles=Math.max(30,PARTICLE_COUNT*0.75|0);
      renderEveryNth=2;
      driftEnabled=true;
    }else{
      activeParticles=PARTICLE_COUNT;
      renderEveryNth=1;
      driftEnabled=true;
    }
  }
}

function animate(){
  t+=0.003;
  frameCount++;
  checkPerformance();

  if(frameCount%renderEveryNth===0){
    renderFractal();
  }
  renderParticles();
  renderGlow();

  requestAnimationFrame(animate);
}

requestAnimationFrame(animate);

window.addEventListener('message',function(e){
  if(e.data==='stop')t=0;
});
})();
</script></body></html>`;
}
