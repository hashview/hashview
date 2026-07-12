/* Dashboard interactive flourish.
 *
 * Loaded ONLY by the dashboard (home.html.j2), so the key-sequence listener
 * below is active on no other page. Visuals are inline/CSS and the logo is
 * cloned from the page's own brand mark. Media (cat images, song) are optional
 * drop-in files under static/ (see window.HV_FX); when absent the effect falls
 * back to a synthesised tune and an emoji so it always works. Nothing is
 * recorded or transmitted — the key buffer only compares against a fixed local
 * string.
 */
(function () {
  'use strict';

  var SEQ = 'oiiaoiia';
  var buf = '';
  var active = false;
  var FX = window.HV_FX || {};

  document.addEventListener('keydown', function (e) {
    if (active) return;
    var k = (e.key || '').toLowerCase();
    if (k.length !== 1 || k < 'a' || k > 'z') return;
    buf = (buf + k).slice(-SEQ.length);
    if (buf === SEQ) { buf = ''; start(); }
  });

  if (window.HV_DASH_AUTOPLAY) {
    window.addEventListener('load', function () { setTimeout(start, 900); });
  }

  // Optional media, probed once. Falls back to emoji / synth if missing.
  var catOk = false, spinOk = false;
  if (FX.cat) { var _pi = new Image(); _pi.onload = function () { catOk = true; }; _pi.src = FX.cat; }
  if (FX.catSpin) { var _ps = new Image(); _ps.onload = function () { spinOk = true; }; _ps.src = FX.catSpin; }
  var song = null, songOk = false;
  if (FX.song) {
    try {
      song = new Audio(FX.song);
      song.preload = 'auto';
      song.addEventListener('canplaythrough', function () { songOk = true; });
      song.addEventListener('error', function () { songOk = false; song = null; });
    } catch (e) { song = null; }
  }

  // ---------------------------------------------------------------- audio ---
  var AC = null;
  function ctx() {
    try {
      if (!AC) AC = new (window.AudioContext || window.webkitAudioContext)();
      if (AC.state === 'suspended') AC.resume();
    } catch (e) { AC = null; }
    return AC;
  }

  var RIFF = [880, 0, 660, 880, 1046, 0, 660, 880, 587, 0, 880, 660];
  var STEP = 0.12;
  function synthTune(maxSec, onEnd) {       // fallback when no song file is present
    var c = ctx();
    if (!c) { if (onEnd) setTimeout(onEnd, maxSec * 1000); return { stop: function () {} }; }
    var master = c.createGain(); master.gain.value = 0.22; master.connect(c.destination);
    var start0 = c.currentTime + 0.05, step = 0, stopped = false, timer = null;
    function note(freq, at) {
      if (!freq) return;
      var o = c.createOscillator(), g = c.createGain();
      o.type = 'square'; o.frequency.setValueAtTime(freq, at);
      o.frequency.linearRampToValueAtTime(freq * 1.02, at + STEP);
      g.gain.setValueAtTime(0.0001, at);
      g.gain.exponentialRampToValueAtTime(0.9, at + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, at + STEP * 0.9);
      o.connect(g); g.connect(master); o.start(at); o.stop(at + STEP);
    }
    function kick(at) {
      var o = c.createOscillator(), g = c.createGain();
      o.type = 'sine'; o.frequency.setValueAtTime(140, at);
      o.frequency.exponentialRampToValueAtTime(50, at + 0.12);
      g.gain.setValueAtTime(0.5, at); g.gain.exponentialRampToValueAtTime(0.0001, at + 0.16);
      o.connect(g); g.connect(master); o.start(at); o.stop(at + 0.18);
    }
    function sched() {
      if (stopped) return;
      while (start0 + step * STEP < c.currentTime + 0.3) {
        var at = start0 + step * STEP;
        if (at - start0 > maxSec) { stop(true); return; }
        note(RIFF[step % RIFF.length], at);
        if (step % 4 === 0) kick(at);
        step++;
      }
    }
    function stop(ended) {
      if (stopped) return; stopped = true;
      if (timer) clearInterval(timer);
      try {
        var n = c.currentTime;
        master.gain.cancelScheduledValues(n);
        master.gain.setValueAtTime(master.gain.value, n);
        master.gain.exponentialRampToValueAtTime(0.0001, n + 0.12);
      } catch (e) {}
      if (ended && onEnd) onEnd();
    }
    timer = setInterval(sched, 60); sched();
    return { stop: function () { stop(false); } };
  }

  // Play a burst; seconds=null means "play to the end" (full show). Uses the
  // real song when available (currentTime persists, so bursts grow naturally),
  // otherwise the synth loop.
  function play(seconds, onEnd) {
    if (songOk && song) {
      try { song.play(); } catch (e) {}
      var t = null;
      if (seconds != null) {
        t = setTimeout(function () { try { song.pause(); } catch (e) {} }, seconds * 1000);
      } else { song.onended = function () { if (onEnd) onEnd(); }; }
      return { stop: function () { if (t) clearTimeout(t); try { song.pause(); } catch (e) {} } };
    }
    return synthTune(seconds == null ? 58 : seconds, onEnd);
  }

  // ---------------------------------------------------------------- visuals -
  var root = null, backdrop = null, style = null, cat = null;
  var curPlay = null, fullTimer = null, fxRAF = null, clones = [], timers = [], catMult = 1;
  var paused = false, blew = false, bgSwirl = false, bounce = false;

  function css() {
    return [
      '#hv-fx{position:fixed;inset:0;z-index:99999;display:flex;align-items:center;',
      'justify-content:center;opacity:0;transition:opacity .6s ease;}',
      '#hv-fx.on{opacity:1;}',
      '#hv-fx-bd{position:absolute;inset:0;background:rgba(4,6,7,.72);backdrop-filter:blur(9px);',
      '-webkit-backdrop-filter:blur(9px);}',
      '#hv-fx-stage{position:relative;z-index:2;display:flex;align-items:center;justify-content:center;}',
      '#hv-fx-sigil{cursor:pointer;filter:drop-shadow(0 0 22px rgba(124,255,107,.6));',
      'animation:hvsig 24s linear infinite;}',
      '#hv-fx-sigil:hover{filter:drop-shadow(0 0 34px rgba(183,255,74,.9));}',
      '#hv-fx-cat{width:150px;height:150px;object-fit:contain;font-size:130px;line-height:150px;',
      'text-align:center;user-select:none;filter:drop-shadow(0 0 18px rgba(124,255,107,.5));}',
      '#hv-fx-cat.spin{animation:hvspin .5s linear infinite;}',
      '#hv-fx-cat.spin-half{animation:hvspin 1s linear infinite;}',
      '.hv-fx-clone{position:absolute;left:0;top:0;width:96px;height:96px;object-fit:contain;',
      'font-size:84px;line-height:96px;text-align:center;pointer-events:none;z-index:1;will-change:transform;}',
      '.hv-fx-confetti{position:absolute;left:0;top:0;border-radius:2px;pointer-events:none;z-index:3;',
      'will-change:transform,opacity;}',
      '@keyframes hvspin{to{transform:rotate(360deg);}}',
      '@keyframes hvsig{from{transform:rotate(0deg) scale(3.4);}to{transform:rotate(360deg) scale(3.4);}}'
    ].join('');
  }

  function start() {
    if (active) return;
    active = true; catMult = 1; paused = false; blew = false; bgSwirl = false; bounce = false;
    style = document.createElement('style'); style.textContent = css();
    document.head.appendChild(style);

    root = document.createElement('div'); root.id = 'hv-fx';
    backdrop = document.createElement('div'); backdrop.id = 'hv-fx-bd';
    var stage = document.createElement('div'); stage.id = 'hv-fx-stage';
    root.appendChild(backdrop); root.appendChild(stage);
    document.body.appendChild(root);
    void root.offsetWidth; root.classList.add('on');

    showSigil(stage);
  }

  function showSigil(stage) {
    var sig = document.createElement('div');
    sig.id = 'hv-fx-sigil';
    var mark = document.querySelector('.brand-mark');
    if (mark) { sig.appendChild(mark.cloneNode(true)); } else { sig.textContent = '#'; }
    stage.appendChild(sig);
    // No build-up sound, no hover timing: a click on the logo drives the sequence.
    sig.addEventListener('click', function () { toCat(stage, sig); });
  }

  function makeCatEl() {
    if (catOk) {
      var img = document.createElement('img');
      img.id = 'hv-fx-cat'; img.alt = '';
      img.src = FX.cat;
      img.onerror = function () { catOk = false; if (cat) { var e = emojiCat(); cat.replaceWith(e); cat = e; } };
      return img;
    }
    return emojiCat();
  }
  function emojiCat() {
    var d = document.createElement('div');
    d.id = 'hv-fx-cat'; d.textContent = '😺';
    return d;
  }

  function toCat(stage, sig) {
    if (cat) return;                          // ignore a second click
    sig.style.pointerEvents = 'none';
    sig.style.transition = 'transform .4s ease, opacity .4s ease';
    sig.style.transform = 'scale(0)'; sig.style.opacity = '0';
    timers.push(setTimeout(function () {
      try { stage.removeChild(sig); } catch (e) {}
      cat = makeCatEl();
      stage.appendChild(cat);
      setCat('still');
      // Hold the still cat for 3s, then start the song and the choreographed intro.
      timers.push(setTimeout(beginShow, 3000));
    }, 340));
  }

  // Cat display states: 'still' image, 'gif' (the spin gif if provided, else a
  // fast CSS rotation of the still), and 'half' (a slow rotation of the still —
  // a gif's native playback rate can't be changed in the browser).
  function setCat(state) {
    if (!cat) return;
    cat.classList.remove('spin', 'spin-half');
    var isImg = cat.tagName === 'IMG';
    if (state === 'still') {
      if (isImg) cat.src = FX.cat;
    } else if (state === 'gif') {
      if (isImg && spinOk) { cat.src = FX.catSpin; }
      else { if (isImg) cat.src = FX.cat; cat.classList.add('spin'); }
    } else if (state === 'half') {
      if (isImg) cat.src = FX.cat;
      cat.classList.add('spin-half');
    }
  }

  // A single-color psychedelic tint on the backdrop, eased between changes.
  function bgTint(bg) {
    if (!backdrop) return;
    backdrop.style.transition = 'background 1.2s ease';
    backdrop.style.background = bg;
  }

  function beginShow() {
    if (!active) return;
    curPlay = play(43.7, null);                       // the song plays normally, stopped at 43.7s
    fullTimer = setTimeout(explode, 42500);           // confetti at 42.5s (song runs on to 43.7s)
    // Intro beats: spin, still, a half-speed spin, still, then the full show.
    setCat('gif');                                                    // 0-2s
    timers.push(setTimeout(function () { setCat('still'); }, 2000));   // 2-3s
    timers.push(setTimeout(function () { setCat('half'); }, 3000));    // 3-5s
    timers.push(setTimeout(function () { setCat('still'); }, 5000));   // 5-6s
    timers.push(setTimeout(psychedelic, 6000));                       // 6s+
    // Background color: four discrete psychedelic tints, then resume the swirl.
    timers.push(setTimeout(function () { bgTint('radial-gradient(circle at 50% 50%,rgba(150,60,255,.45),rgba(4,6,7,.78))'); }, 12500));  // violet
    timers.push(setTimeout(function () { bgTint('radial-gradient(circle at 50% 50%,rgba(0,190,255,.45),rgba(4,6,7,.78))'); }, 14000));   // cyan
    timers.push(setTimeout(function () { bgTint('radial-gradient(circle at 50% 50%,rgba(255,40,150,.45),rgba(4,6,7,.78))'); }, 15500));  // magenta
    timers.push(setTimeout(function () { bgTint('radial-gradient(circle at 50% 50%,rgba(120,255,90,.45),rgba(4,6,7,.78))'); }, 17000));  // acid green
    timers.push(setTimeout(function () { if (backdrop) backdrop.style.transition = 'none'; bgSwirl = true; }, 19000));   // resume swirl
    // Freeze every cat at 30s; at 32s (2s later) resume — but into screensaver
    // bounce mode (still pngs, no spin) — and double the swarm (from song start).
    timers.push(setTimeout(function () { paused = true; }, 30000));
    timers.push(setTimeout(function () { paused = false; catMult = 2; bounce = true; }, 32000));
  }

  function psychedelic() {
    if (!active) return;
    cat.classList.remove('spin', 'spin-half');
    if (cat.tagName === 'IMG' && spinOk) { cat.src = FX.catSpin; }   // keep the cat spinning
    // Lift the blur so the (now psychedelic) dashboard shows through.
    backdrop.style.backdropFilter = 'none';
    backdrop.style.webkitBackdropFilter = 'none';

    var t0 = performance.now(), spawned = 0, pausedMs = 0, pauseAt = null;
    var prevNow = t0, catFrozen = null, catB = null, bounceCulled = false;
    function frame(now) {
      if (paused) {
        if (pauseAt === null) {                        // on entry: snap every cat to the
          pauseAt = now;                               // still png, upright, at its current
          var elP = (now - pausedMs - t0) / 1000;      // size and position, then hold it
          var kP = Math.min(elP / 14, 1);
          var Wp = window.innerWidth, Hp = window.innerHeight, Mp = 160;
          if (cat) {
            if (cat.tagName === 'IMG' && spinOk) cat.src = FX.cat;
            var cfx = kP * 120 * Math.sin(elP * 1.7), cfy = kP * 80 * Math.cos(elP * 2.3);
            var cfs = 1 + 0.4 * kP * Math.sin(elP * 7);
            cat.style.transform = 'translate(' + cfx + 'px,' + cfy + 'px) scale(' + cfs + ')';
            catFrozen = { x: cfx, y: cfy, s: cfs };    // seeds the bounce start position
          }
          clones.forEach(function (o) {
            if (catOk && spinOk && o.gif) { o.gif = false; o.el.src = FX.cat; }
            var Wm = Wp + 2 * Mp, Hm = Hp + 2 * Mp;
            var x = ((o.x + o.vx * elP) % Wm + Wm) % Wm - Mp;
            var y = ((o.y + o.vy * elP) % Hm + Hm) % Hm - Mp;
            var s = Math.max(0.15, o.base + o.amp * Math.sin(elP * o.freq + o.ph));
            o.el.style.transform = 'translate(' + x + 'px,' + y + 'px) scale(' + s + ')';   // upright
            o.fx = x; o.fy = y; o.fs = s;              // seeds the bounce start position
          });
        }
        fxRAF = requestAnimationFrame(frame);
        return;                                        // hold this tableau until 30s
      }
      if (pauseAt !== null) {                          // resume (into bounce mode) with no time jump
        pausedMs += now - pauseAt; pauseAt = null;
      }
      var el = (now - t0 - pausedMs) / 1000, k = Math.min(el / 14, 1);
      var dt = Math.min(0.05, (now - prevNow) / 1000); prevNow = now;   // frame delta for bounce
      var W = window.innerWidth, H = window.innerHeight, M = 160;
      // Background: once the swirl resumes (19s), pulse + rotate hue at the
      // original frequency. Before that the discrete tints (set on timers) hold.
      if (bgSwirl) {
        var bright = 1 + 0.12 * k * Math.sin(el * 5);   // gentle pulse (not a strobe)
        backdrop.style.filter = 'hue-rotate(' + (el * 130) + 'deg) saturate(' + (1 + k * 2.2) +
          ') brightness(' + bright + ')';
        backdrop.style.background = 'radial-gradient(circle at 50% 50%,rgba(' + (60 + 120 * k) +
          ',20,' + (90 + 100 * k) + ',.38),rgba(4,6,7,.6))';
      }
      // Center cat. Until 32s it drifts + pulses (spinning); from 32s it bounces
      // around like a screensaver — still png, upright, no spin.
      if (cat) {
        if (bounce) {
          if (cat.tagName === 'IMG' && spinOk) cat.src = FX.cat;
          if (!catB) {
            var cf = catFrozen || { x: 0, y: 0, s: 1 };
            var ca = Math.random() * 6.283;
            catB = { x: cf.x, y: cf.y, s: cf.s, vx: Math.cos(ca) * 900, vy: Math.sin(ca) * 900 };   // 6x base speed
          }
          catB.x += catB.vx * dt; catB.y += catB.vy * dt;
          var chw = 75 * catB.s, cLimX = Math.max(0, W / 2 - chw), cLimY = Math.max(0, H / 2 - chw);
          if (catB.x < -cLimX) { catB.x = -cLimX; catB.vx = Math.abs(catB.vx); }
          else if (catB.x > cLimX) { catB.x = cLimX; catB.vx = -Math.abs(catB.vx); }
          if (catB.y < -cLimY) { catB.y = -cLimY; catB.vy = Math.abs(catB.vy); }
          else if (catB.y > cLimY) { catB.y = cLimY; catB.vy = -Math.abs(catB.vy); }
          cat.style.transform = 'translate(' + catB.x + 'px,' + catB.y + 'px) scale(' + catB.s + ')';
        } else {
          var sc = 1 + 0.4 * k * Math.sin(el * 7);
          var dx = k * 120 * Math.sin(el * 1.7), dy = k * 80 * Math.cos(el * 2.3);
          var gifSpin = cat.tagName === 'IMG' && spinOk;
          cat.style.transform = 'translate(' + dx + 'px,' + dy + 'px) scale(' + sc + ')' +
            (gifSpin ? '' : ' rotate(' + (el * 720) + 'deg)');
        }
      }
      // A swarm of cats. Ramps to 26, then doubles to 52 at the 32s resume.
      var want = Math.floor(k * 26) * catMult;
      while (spawned < want) {
        var cl = catOk ? document.createElement('img') : document.createElement('div');
        cl.className = 'hv-fx-clone';
        var startGif = !bounce && catOk && spinOk && Math.random() < 0.5;   // still png once bouncing
        if (catOk) { cl.src = startGif ? FX.catSpin : FX.cat; cl.alt = ''; } else { cl.textContent = '😺'; }
        root.appendChild(cl);
        clones.push({
          el: cl,
          x: Math.random() * W, y: Math.random() * H,       // start anywhere on screen
          vx: (Math.random() * 2 - 1) * 200,                 // px/s, any horizontal dir
          vy: (Math.random() * 2 - 1) * 200,                 // px/s, any vertical dir
          base: 0.5 + Math.random() * 2.6,                   // size variety
          amp: 0.8 + Math.random() * 4.4,                    // zoom depth (max ~2x bigger)
          freq: 0.5 + Math.random() * 2,                     // zoom speed
          ph: Math.random() * 6.283,                         // phase -> mix of in/out
          rot: (Math.random() * 2 - 1) * 320,                // deg/s, either direction
          gif: startGif,                                     // currently showing the spin gif?
          nextFlip: el + 0.3 + Math.random() * 2.2           // when to next toggle still<->spin
        });
        spawned++;
      }
      // Entering screensaver: keep only the smaller half of the swarm by size;
      // shrink the larger half out of existence over ~.15s.
      if (bounce && !bounceCulled) {
        bounceCulled = true;
        clones.forEach(function (o) { o._sz = (o.fs != null) ? o.fs : o.base; });
        clones.sort(function (a, b) { return a._sz - b._sz; });
        var keepN = Math.floor(clones.length / 2);
        var doomed = clones.slice(keepN);
        doomed.forEach(function (o) {                    // pin each at its current spot, full size
          var hw = 48 * o._sz, has = o.fx != null;
          o._tx = has ? o.fx : (hw + Math.random() * Math.max(1, W - 2 * hw)) - 48;
          o._ty = has ? o.fy : (hw + Math.random() * Math.max(1, H - 2 * hw)) - 48;
          o.el.style.transition = 'none';
          o.el.style.transform = 'translate(' + o._tx + 'px,' + o._ty + 'px) scale(' + o._sz + ')';
        });
        void root.offsetWidth;                           // commit start state before animating
        doomed.forEach(function (o) {                    // then shrink to nothing and drop
          o.el.style.transition = 'transform .15s ease-in';
          o.el.style.transform = 'translate(' + o._tx + 'px,' + o._ty + 'px) scale(0)';
          setTimeout(function () { try { o.el.remove(); } catch (e) {} }, 170);
        });
        clones = clones.slice(0, keepN);
      }
      clones.forEach(function (o) {
        if (bounce) {
          // Screensaver bounce: still png, upright, straight lines reflecting off
          // the walls. Seeded from each cat's frozen position/size (new cats start
          // at a random spot).
          if (!o.bInit) {
            o.bInit = true;
            o.bs = (o.fs != null) ? o.fs : o.base;
            var hw0 = 48 * o.bs;
            if (o.fx != null) { o.cx = o.fx + 48; o.cy = o.fy + 48; }
            else { o.cx = hw0 + Math.random() * Math.max(1, W - 2 * hw0); o.cy = hw0 + Math.random() * Math.max(1, H - 2 * hw0); }
            var mag = Math.sqrt(o.vx * o.vx + o.vy * o.vy) || 1, spd = (120 + Math.random() * 90) * 6;   // 6x base speed
            o.bvx = o.vx / mag * spd; o.bvy = o.vy / mag * spd;
            if (o.el.tagName === 'IMG' && spinOk) o.el.src = FX.cat;
          }
          o.cx += o.bvx * dt; o.cy += o.bvy * dt;
          var hw = 48 * o.bs;
          if (o.cx < hw) { o.cx = hw; o.bvx = Math.abs(o.bvx); }
          else if (o.cx > W - hw) { o.cx = W - hw; o.bvx = -Math.abs(o.bvx); }
          if (o.cy < hw) { o.cy = hw; o.bvy = Math.abs(o.bvy); }
          else if (o.cy > H - hw) { o.cy = H - hw; o.bvy = -Math.abs(o.bvy); }
          o.el.style.transform = 'translate(' + (o.cx - 48) + 'px,' + (o.cy - 48) + 'px) scale(' + o.bs + ')';
        } else {
          var Wm = W + 2 * M, Hm = H + 2 * M;
          // Fly across the screen and wrap around the edges (keeps them moving).
          var x = ((o.x + o.vx * el) % Wm + Wm) % Wm - M;
          var y = ((o.y + o.vy * el) % Hm + Hm) % Hm - M;
          var s = Math.max(0.15, o.base + o.amp * Math.sin(el * o.freq + o.ph));   // zoom in/out
          // Each cat flips between still and spinning on its own random schedule.
          if (catOk && spinOk && el >= o.nextFlip) {
            o.gif = !o.gif;
            o.el.src = o.gif ? FX.catSpin : FX.cat;
            o.nextFlip = el + 0.3 + Math.random() * 2.2;
          }
          o.el.style.transform = 'translate(' + x + 'px,' + y + 'px) scale(' + s +
            ') rotate(' + (el * o.rot) + 'deg)';
        }
        o.el.style.filter = 'hue-rotate(' + (el * 200 + o.base * 180) + 'deg)';
      });
      fxRAF = requestAnimationFrame(frame);
    }
    fxRAF = requestAnimationFrame(frame);
  }

  // Conclusion: every cat detonates into confetti where it stands, the confetti
  // arcs out under gravity and fades, then the overlay tears down (colors back
  // to normal).
  function explode() {
    if (!active || blew) return;
    blew = true;
    if (fxRAF) { cancelAnimationFrame(fxRAF); fxRAF = null; }
    // Leave the song playing — it runs on to its own 43s stop; finish() clears it.

    var COLORS = ['#ff4d6d', '#ffd23f', '#3ddc97', '#4dabf7', '#c77dff', '#ff922b', '#ffffff'];
    var cats = [];
    if (cat) cats.push(cat);
    clones.forEach(function (o) { cats.push(o.el); });
    var parts = [];
    cats.forEach(function (el) {
      var r = el.getBoundingClientRect();
      var cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      var n = 10 + Math.floor(Math.random() * 8);           // confetti bits per cat
      for (var i = 0; i < n; i++) {
        var p = document.createElement('div');
        p.className = 'hv-fx-confetti';
        p.style.background = COLORS[Math.floor(Math.random() * COLORS.length)];
        var w = 7 + Math.random() * 8;
        p.style.width = w + 'px';
        p.style.height = (w * (0.4 + Math.random() * 0.8)) + 'px';
        root.appendChild(p);
        var ang = Math.random() * 6.283, spd = 220 + Math.random() * 520;
        parts.push({
          el: p, x: cx, y: cy,
          vx: Math.cos(ang) * spd,
          vy: Math.sin(ang) * spd - 240,                    // pop upward before gravity wins
          spin: Math.random() * 360,
          rot: (Math.random() * 2 - 1) * 900
        });
      }
      try { el.remove(); } catch (e) {}
    });
    clones = []; cat = null;

    var G = 1400, t0 = performance.now();                   // gravity, px/s^2
    function boom(now) {
      var el = (now - t0) / 1000;
      if (el > 1.8) { finish(); return; }
      var op = Math.max(0, 1 - Math.max(0, el - 0.8) / 1.0);   // fade over the last second
      parts.forEach(function (p) {
        var x = p.x + p.vx * el;
        var y = p.y + p.vy * el + 0.5 * G * el * el;
        p.el.style.transform = 'translate(' + x + 'px,' + y + 'px) rotate(' + (p.spin + p.rot * el) + 'deg)';
        p.el.style.opacity = op;
      });
      fxRAF = requestAnimationFrame(boom);
    }
    fxRAF = requestAnimationFrame(boom);
  }

  function finish() {
    if (!active) return;
    timers.forEach(clearTimeout);
    timers = [];
    if (fullTimer) clearTimeout(fullTimer);
    if (fxRAF) cancelAnimationFrame(fxRAF);
    if (curPlay) curPlay.stop();
    if (song) { try { song.pause(); song.currentTime = 0; song.onended = null; } catch (e) {} }
    fullTimer = fxRAF = curPlay = null;
    clones = [];
    if (root) {
      root.classList.remove('on');
      var r = root, s = style;
      setTimeout(function () { try { r.remove(); } catch (e) {} try { s.remove(); } catch (e) {} }, 650);
    }
    root = backdrop = style = cat = null;
    active = false;
  }
})();
