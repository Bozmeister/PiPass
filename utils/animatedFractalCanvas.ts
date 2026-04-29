// Generates the standalone HTML/JS document used by the WebView /
// iframe inside AnimatedFractalView.
//
// T001-T010 — Reactive Security Layer.
// The fractal math itself (Mandelbrot iteration, drift, particles,
// glow) is UNCHANGED. Everything new is layered on top via:
//   - a small `__fractal.setSecurity({...})` API that the host calls
//     when SecurityState changes (throttled to ≤10/sec on the host)
//   - per-frame lerp of current → target so visual changes are
//     smooth rather than snapping (T005)
//   - five derived parameters (colorShift / glowMul / distortion /
//     flickerAmp / ripple) that modulate the existing pipeline
//   - FAIL-OPEN: the API and its consumer are wrapped in try/catch.
//     If `setSecurity` is never called the values stay at neutral
//     defaults and the fractal renders exactly as before.

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

// =====================================================================
// Reactive Security Layer (T001-T010).
//
// secCurrent  — what the renderer is using right now (per frame).
// secTarget   — what the host last pushed via setSecurity().
// Each frame we lerp current toward target with factor LERP_FACTOR.
// All inputs default to neutral (no visual change vs. pre-spec).
// =====================================================================
var LERP_FACTOR=0.05;
var secCurrent={hueShift:0,glowMul:1,distortion:0,flickerAmp:0,ripple:0};
var secTarget={hueShift:0,glowMul:1,distortion:0,flickerAmp:0,ripple:0};
// Sampled once per frame so the per-pixel inner loop reads locals
// (significantly faster than property-of-object access in a 250k-pixel hot loop).
var frameHueShift=0;
var frameGlowMul=1;
var frameEscapeR2=4;
var frameFlickerOffset=0;
var frameRippleAmp=0.015;
var frameDriftAmp=0.003;

function lerp(a,b,t){return a+(b-a)*t;}

function tickSecurity(){
  // Smooth current toward target. Even when the host stops pushing
  // updates, this loop is a no-op (delta is 0) so it's free.
  secCurrent.hueShift=lerp(secCurrent.hueShift,secTarget.hueShift,LERP_FACTOR);
  secCurrent.glowMul=lerp(secCurrent.glowMul,secTarget.glowMul,LERP_FACTOR);
  secCurrent.distortion=lerp(secCurrent.distortion,secTarget.distortion,LERP_FACTOR);
  secCurrent.flickerAmp=lerp(secCurrent.flickerAmp,secTarget.flickerAmp,LERP_FACTOR);
  secCurrent.ripple=lerp(secCurrent.ripple,secTarget.ripple,LERP_FACTOR);

  // Snapshot to locals for the inner loop.
  frameHueShift=secCurrent.hueShift;
  frameGlowMul=secCurrent.glowMul;
  // Distortion bumps the bailout radius slightly: 4 → up to ~5.
  // This perturbs the iteration boundary without changing the math.
  frameEscapeR2=4+secCurrent.distortion*4;
  // Flicker is sampled once per frame (cheap) and added uniformly
  // to all rendered pixels — visually equivalent to subtle global
  // brightness jitter, and cheap enough to leave on at idle.
  frameFlickerOffset=
    secCurrent.flickerAmp>0
      ? (Math.random()-0.5)*secCurrent.flickerAmp*60
      : 0;
  // Ripple bumps the existing zoom-oscillation amplitude. Pulses
  // visibly in the "new device just signed in" state.
  frameRippleAmp=0.015+secCurrent.ripple;
  frameDriftAmp=0.003+secCurrent.distortion*0.001;
}

window.__fractal_setSecurity=function(s){
  // FAIL-OPEN: any malformed input is silently ignored — secTarget
  // keeps its previous value and the fractal continues animating.
  try{
    if(!s||typeof s!=='object')return;
    var levelMap={normal:0,elevated:0.33,high:0.66,critical:1};
    var lvl=typeof s.securityLevel==='string'?levelMap[s.securityLevel]:undefined;
    if(typeof lvl!=='number')lvl=0;
    var raw=typeof s.threatLevel==='number'&&isFinite(s.threatLevel)?s.threatLevel:0;
    var intensity=Math.max(0,Math.min(100,raw))/100;

    secTarget.hueShift=lvl;
    // 0.5..2.0 multiplier on brightness/glow.
    secTarget.glowMul=0.5+intensity*1.5;
    // Recovery overrides intensity-based distortion with a stable 0.3.
    secTarget.distortion=s.recoveryMode?0.3:intensity*0.2;
    // Subtle flicker only when an anomaly was reported recently.
    secTarget.flickerAmp=s.hasRecentAnomalies?0.1:0;
    // New-device ripple amplitude (extra zoom-pulse).
    secTarget.ripple=s.isNewDevice?0.05:0;
  }catch(e){}
};

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
  // Use the per-frame snapshots set by tickSecurity(). When setSecurity
  // has never been called these are all neutral (frameHueShift=0,
  // frameGlowMul=1, frameEscapeR2=4, frameFlickerOffset=0,
  // frameRippleAmp=0.015) → identical output to the original.
  var rippleAmp=frameRippleAmp;
  var driftAmp=frameDriftAmp;

  var zoomAnimated=driftEnabled?ZOOM*(1+Math.sin(t*driftSpeed)*rippleAmp):ZOOM;
  var oxAnimated=driftEnabled?Math.cos(t*driftSpeed*0.6)*driftAmp:0;
  var oyAnimated=driftEnabled?Math.sin(t*driftSpeed*0.8)*driftAmp:0;

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

  // Pre-bind security frame locals so the inner loop avoids global lookups.
  var hueShift=frameHueShift;
  var glowMul=frameGlowMul;
  var escapeR2=frameEscapeR2;
  var flickerOffset=frameFlickerOffset;
  // Channel rebalance coefficients pre-computed from hueShift.
  // hueShift 0 → identity; hueShift 1 → strong red, dampened green/blue.
  var redLift=hueShift*0.55;          // pulls r0 toward 255
  var greenAtten=1-hueShift*0.55;     // dampens g0
  var blueAtten=1-hueShift*0.4;       // dampens b0

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
        if(zr2+zi2>escapeR2)break;
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
        var bright=(1.0+shimmer*(norm>0.3&&norm<0.95?1.0:0.3))*glowMul;
        var r0=(c0[0]+(c1[0]-c0[0])*frac)*bright;
        var g0=(c0[1]+(c1[1]-c0[1])*frac)*bright;
        var b0=(c0[2]+(c1[2]-c0[2])*frac)*bright;
        // Hue shift: bias palette from green → yellow/orange/red as
        // security level rises. Done after palette interp so the
        // gradient direction is preserved; only the channel ratio shifts.
        if(hueShift>0){
          r0=r0+(255-r0)*redLift;
          g0=g0*greenAtten;
          b0=b0*blueAtten;
        }
        // Per-frame brightness flicker (sampled in tickSecurity).
        if(flickerOffset!==0){
          r0+=flickerOffset;
          g0+=flickerOffset;
          b0+=flickerOffset;
        }
        var ir=r0|0;var ig=g0|0;var ib=b0|0;
        if(ir<0)ir=0;else if(ir>255)ir=255;
        if(ig<0)ig=0;else if(ig>255)ig=255;
        if(ib<0)ib=0;else if(ib>255)ib=255;
        buf[idx]=ir;
        buf[idx+1]=ig;
        buf[idx+2]=ib;
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
  // Particle color reflects security band so the ring of orbiting
  // particles agrees visually with the body of the fractal. We
  // build the rgb string once per frame, not per particle.
  var hue=frameHueShift;
  var pr=Math.round(0+(255-0)*hue);
  var pg=Math.round(255-(255-80)*hue);
  var pb=Math.round(136-(136-30)*hue);
  // Glow opacity tracks glowMul — softer at calm, brighter at threat.
  var gMul=Math.max(0.6,Math.min(1.6,frameGlowMul));
  var glowColor='rgba('+pr+','+pg+','+pb+',0.6)';
  ctx.save();
  ctx.globalCompositeOperation='lighter';
  for(var i=0;i<activeParticles;i++){
    var p=particles[i];
    p.angle+=p.speed;
    var ppx=cx2+Math.cos(p.angle)*p.radius*radius;
    var ppy=cy2+Math.sin(p.angle)*p.radius*radius;
    var dx=ppx-cx2;
    var dy=ppy-cy2;
    if(dx*dx+dy*dy>(radius*radius))continue;
    ctx.beginPath();
    ctx.arc(ppx,ppy,p.size,0,Math.PI*2);
    ctx.fillStyle='rgba('+pr+','+pg+','+pb+','+(p.opacity*gMul)+')';
    ctx.shadowColor=glowColor;
    ctx.shadowBlur=4*gMul;
    ctx.fill();
  }
  ctx.restore();
}

function renderGlow(){
  var radius=W/2;
  var cx2=W/2;
  var cy2=H/2;
  // Outer glow color shifts with security level too, so a critical
  // alarm bathes the ring in red rather than green.
  var hue=frameHueShift;
  var gr=Math.round(0+(255-0)*hue);
  var gg=Math.round(255-(255-80)*hue);
  var gb=Math.round(136-(136-30)*hue);
  var glowAlpha=0.08*Math.max(0.6,Math.min(1.8,frameGlowMul));

  ctx.save();
  var grad=ctx.createRadialGradient(cx2,cy2,radius*0.6,cx2,cy2,radius);
  grad.addColorStop(0,'rgba('+gr+','+gg+','+gb+',0)');
  grad.addColorStop(1,'rgba('+gr+','+gg+','+gb+','+glowAlpha+')');
  ctx.fillStyle=grad;
  ctx.beginPath();
  ctx.arc(cx2,cy2,radius,0,Math.PI*2);
  ctx.fill();
  ctx.restore();

  ctx.save();
  ctx.globalCompositeOperation='lighter';
  ctx.filter='blur(8px)';
  ctx.globalAlpha=0.06*Math.max(0.7,Math.min(1.6,frameGlowMul));
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
  // Always tick security (cheap) so the lerp progresses even on
  // skipped fractal-render frames.
  tickSecurity();

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

window.__fractal={
  pause:pauseAnim,
  resume:resumeAnim,
  setSecurity:window.__fractal_setSecurity
};

document.addEventListener('visibilitychange',function(){
  if(document.hidden)pauseAnim();else resumeAnim();
});

animId=requestAnimationFrame(animate);

window.addEventListener('message',function(e){
  // String commands (existing): pause / resume.
  if(e.data==='pause')pauseAnim();
  else if(e.data==='resume')resumeAnim();
  else if(e.data&&typeof e.data==='object'&&e.data.type==='security'){
    // Object messages from the iframe host (web). Native uses
    // injectJavaScript instead, calling __fractal.setSecurity directly.
    try{window.__fractal_setSecurity(e.data.payload);}catch(err){}
  }
});
})();
</script></body></html>`;
}
