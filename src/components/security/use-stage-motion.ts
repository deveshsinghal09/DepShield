import {useEffect,type RefObject} from 'react';

export function useStageIntro(root:RefObject<HTMLElement|null>) {
  useEffect(()=>{
    const stage=root.current;
    if(!stage || !Element.prototype.animate || matchMedia('(prefers-reduced-motion: reduce)').matches)return;
    const animations:Animation[]=[];
    let disposed=false,started=false,frame=0;
    const finish=()=>{stage.classList.remove('intro');animations.forEach(a=>a.cancel());};
    const start=()=>{
      if(disposed||started)return;started=true;stage.classList.add('intro');
      const probe=document.createElement('div');probe.style.width='calc(100 * var(--s))';stage.append(probe);const s=probe.getBoundingClientRect().width/100;probe.remove();
      const speed=innerWidth<600?.86:1,expo='cubic-bezier(.16,1,.3,1)',quint='cubic-bezier(.22,1,.36,1)',quart='cubic-bezier(.25,1,.5,1)';
      const animate=(selector:string,keys:Keyframe[],t:number,d:number,easing:string,stagger=0)=>stage.querySelectorAll(selector).forEach((el,i)=>animations.push(el.animate(keys,{duration:d*1000*speed,delay:(t+i*stagger)*1000*speed,easing,fill:'both'})));
      const rise=(selector:string,y:number,t:number,d:number,easing:string,stagger=0)=>animate(selector,[{opacity:0,transform:`translateY(${y*s}px)`},{opacity:1,transform:'translateY(0)'}],t,d,easing,stagger);
      animate('.logo',[{opacity:0,transform:'scale(.9)'},{opacity:1,transform:'scale(1)'}],0,.7,expo);
      rise('.navitem',7,.12,.62,quint,.055);rise('.burger',0,.18,.55,quart);
      animate('.btn-top',[{clipPath:'inset(0 100% 0 0)'},{clipPath:'inset(0 0 0 0)'}],.28,.66,expo);
      animate('.ln>span',[{transform:'translateY(120%)'},{transform:'translateY(0)'}],.34,.98,'cubic-bezier(.22,.85,.24,1)',.09);
      rise('.sub',14,.74,.72,quint);animate('.btn-cta',[{clipPath:'inset(0 100% 0 0)'},{clipPath:'inset(0 0 0 0)'}],.9,.7,expo);
      animate('.rule',[{transform:'scaleY(0)'},{transform:'scaleY(1)'}],.98,.6,quart,.07);rise('.num',12,1.04,.66,quint,.085);rise('.lab',10,1.1,.62,quint,.085);
      Promise.all(animations.map(a=>a.finished.catch(()=>{}))).then(finish);
    };
    const fontsTimeout=setTimeout(start,1000),deadline=setTimeout(finish,4000);
    document.fonts.ready.then(()=>{if(!disposed)frame=requestAnimationFrame(start);});
    const motion=matchMedia('(prefers-reduced-motion: reduce)');const onMotion=()=>{if(motion.matches){started=true;finish();}};motion.addEventListener('change',onMotion);
    return()=>{disposed=true;cancelAnimationFrame(frame);clearTimeout(fontsTimeout);clearTimeout(deadline);motion.removeEventListener('change',onMotion);finish();};
  },[root]);
}
