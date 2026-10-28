'use client';

import {useEffect,useRef,useState} from 'react';
import {useRouter} from 'next/navigation';
import {destinations} from './content';
import {SecurityHero,SecurityStats,type LandingSummary} from './hero';
import {MobileMenu,SecurityHeader} from './navigation';
import {VideoGrades,VideoPlate} from './video-background';
import {useStageIntro} from './use-stage-motion';

/** Native React composition of the approved reference. Add new sections here, not to the standalone export. */
export function SecurityLanding({summary}:{summary:LandingSummary}) {
  const router=useRouter();
  const root=useRef<HTMLElement>(null),burger=useRef<HTMLButtonElement>(null);
  const primary=useRef<HTMLVideoElement>(null),lift=useRef<HTMLVideoElement>(null),texture=useRef<HTMLVideoElement>(null);
  const [open,setOpen]=useState(false),[active,setActive]=useState<string|null>(null);
  useStageIntro(root);
  useEffect(()=>{
    const videos=[primary.current,lift.current,texture.current].filter((v):v is HTMLVideoElement=>Boolean(v));
    const motion=matchMedia('(prefers-reduced-motion: reduce)');
    const update=()=>syncPlayback();
    function syncPlayback(){videos.forEach(v=>{v.muted=true;if(motion.matches||document.hidden)v.pause();else void v.play().catch(()=>{});});}
    const syncTime=()=>{const master=videos[0];videos.slice(1).forEach(v=>{if(v.readyState&&Math.abs(v.currentTime-master.currentTime)>.12)v.currentTime=master.currentTime;});};
    videos.forEach(v=>v.addEventListener('loadeddata',syncPlayback));videos[0]?.addEventListener('timeupdate',syncTime);
    document.addEventListener('visibilitychange',syncPlayback);motion.addEventListener('change',update);update();
    return()=>{videos.forEach(v=>{v.pause();v.removeEventListener('loadeddata',syncPlayback);});videos[0]?.removeEventListener('timeupdate',syncTime);document.removeEventListener('visibilitychange',syncPlayback);motion.removeEventListener('change',update);};
  },[]);
  useEffect(()=>{
    if(!open)return;
    root.current?.querySelector<HTMLAnchorElement>('#security-menu a')?.focus();
    const close=()=>{setOpen(false);setActive(null);burger.current?.focus();};
    const key=(e:KeyboardEvent)=>{
      if(e.key==='Escape'){e.preventDefault();close();}
      if(e.key==='Tab'){
        const controls=[burger.current,...Array.from(root.current?.querySelectorAll<HTMLElement>('#security-menu a,#security-menu button')??[])].filter((el):el is HTMLElement=>Boolean(el?.getClientRects().length));
        const i=controls.indexOf(document.activeElement as HTMLElement);
        if(e.shiftKey&&i<=0){e.preventDefault();controls.at(-1)?.focus();}else if(!e.shiftKey&&i===controls.length-1){e.preventDefault();controls[0]?.focus();}
      }
    };
    const desktop=matchMedia('(min-width:1024px)');const resize=()=>{if(desktop.matches)close();};
    document.addEventListener('keydown',key);desktop.addEventListener('change',resize);
    return()=>{document.removeEventListener('keydown',key);desktop.removeEventListener('change',resize);};
  },[open]);
  useEffect(()=>{
    const key=(e:KeyboardEvent)=>{if(e.key==='Escape')setActive(null);};
    const click=(e:MouseEvent)=>{if(e.target instanceof Element&&!e.target.closest('.navitem,.mitem'))setActive(null);};
    document.addEventListener('keydown',key);document.addEventListener('click',click);
    return()=>{document.removeEventListener('keydown',key);document.removeEventListener('click',click);};
  },[]);
  const home=()=>{setOpen(false);setActive(null);if(open)burger.current?.focus();};
  const select=(label:string)=>{home();router.push(destinations[label]??'/scan');};
  const nav={active,onToggle:(id:string)=>setActive(value=>value===id?null:id),onSelect:select,onHome:home};
  return <main ref={root} className={`security-stage${open?' nav-open':''}`} data-ui="security-stage">
    <VideoGrades/><VideoPlate className="bg" videoRef={primary}/><VideoPlate className="bg2" videoRef={lift}/><div className="scrim"/>
    <div className="frame" inert={open}><SecurityHeader {...nav}/><div className="sp sp-a"/><SecurityHero onSecure={()=>select('Scan project')}/><div className="sp sp-b"/><SecurityStats summary={summary}/><div className="sp sp-c"/></div>
    <MobileMenu {...nav} open={open} texture={<VideoPlate className="menu-tex" videoRef={texture}/>}/>
    <button ref={burger} className="burger" aria-label={open?'Close menu':'Open menu'} aria-controls="security-menu" aria-expanded={open} onClick={()=>{setOpen(!open);setActive(null);}}><i/><i/><i/></button>
    <p className="preview-note">DepShield · Dependency Risk Console</p>
  </main>;
}
