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

var PALETTE=[
  [0x00,0x11,0x00],
  [0x00,0x22,0x00],
  [0x00,0x33,0x00],
  [0x00,0x44,0x00],
  [0x00,0x66,0x00],
  [0x00,0xaa,0x55],
  [0x00,0xff,0x88],
  [0x66,0xff,0xcc],
  [0xcc,0xff,0xee],
  [0xff,0xff,0xff]
];
var PLEN=PALETTE.length;

var PARTICLE_COUNT=60;
var particles=[];
for(var i=0;i<PARTICLE_COUNT;i++){
  particles.push({
    angle:seededRandom(i)*Math.PI*2,
    radius:0.92+seededRandom(i+99)*0.05,
    speed:0.0004+seededRandom(i+199)*0.0004,
    size:1+seededRandom(i+299)*1.5,
    opacity:0.05+seededRandom(i+399)*0.1
  });
}

var activeParticles=PARTICLE_COUNT;
var renderEveryNth=1;
var frameCount=0;
var driftEnabled=true;

var fpsHistory=[];
var lastFrameTime=performance.now();
var fpsCheckTimer=0;

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

  var shimmer=Math.sin(t*0.8)*0.08;

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
        buf[idx]=0;buf[idx+1]=0;buf[idx+2]=0;buf[idx+3]=255;
      }else{
        var norm=iter/MAX_ITER;
        var scaled=Math.pow(norm,0.35)*(PLEN-1);
        var pi=scaled|0;
        if(pi>PLEN-2)pi=PLEN-2;
        var frac=scaled-pi;
        var c0=PALETTE[pi];
        var c1=PALETTE[pi+1];
        var bright=1.0+shimmer*(norm>0.3&&norm<0.95?1.0:0.3);
        var r0=((c0[0]+(c1[0]-c0[0])*frac)*bright)|0;
        var g0=((c0[1]+(c1[1]-c0[1])*frac)*bright)|0;
        var b0=((c0[2]+(c1[2]-c0[2])*frac)*bright)|0;
        buf[idx]=r0>255?255:r0;
        buf[idx+1]=g0>255?255:g0;
        buf[idx+2]=b0>255?255:b0;
        buf[idx+3]=255;
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
    ctx.fillStyle='rgba(0,255,136,'+p.opacity+')';
    ctx.shadowColor='rgba(0,255,136,0.6)';
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
  grad.addColorStop(0,'rgba(0,255,136,0)');
  grad.addColorStop(1,'rgba(0,255,136,0.08)');
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
  if(paused)return;
  t+=0.003;
  frameCount++;
  checkPerformance();

  if(frameCount%renderEveryNth===0){
    renderFractal();
  }
  renderParticles();
  renderGlow();

  animId=requestAnimationFrame(animate);
}

var paused=false;
var animId=0;

function resumeAnim(){
  if(!paused)return;
  paused=false;
  lastFrameTime=performance.now();
  animId=requestAnimationFrame(animate);
}

function pauseAnim(){
  paused=true;
  if(animId)cancelAnimationFrame(animId);
  animId=0;
}

window.__fractal={pause:pauseAnim,resume:resumeAnim};

document.addEventListener('visibilitychange',function(){
  if(document.hidden)pauseAnim();else resumeAnim();
});

animId=requestAnimationFrame(animate);

window.addEventListener('message',function(e){
  if(e.data==='pause')pauseAnim();
  else if(e.data==='resume')resumeAnim();
});
})();
</script></body></html>`;
}
