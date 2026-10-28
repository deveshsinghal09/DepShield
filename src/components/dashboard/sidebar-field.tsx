'use client';

import {useEffect,useRef} from 'react';

/** Decorative real-time 3D terrain, not a representation of scan activity. */
export function SidebarField(){
  const canvas=useRef<HTMLCanvasElement>(null);
  useEffect(()=>{
    let disposed=false,cleanup=()=>{};
    void import('three').then(T=>{
      if(disposed||!canvas.current)return;
      const element=canvas.current;
      let renderer:InstanceType<typeof T.WebGLRenderer>;
      try{renderer=new T.WebGLRenderer({canvas:element,alpha:true,antialias:true,powerPreference:'low-power'});}catch{return;}
      renderer.setPixelRatio(Math.min(devicePixelRatio,1.5));
      const scene=new T.Scene();scene.fog=new T.FogExp2('#111113',.055);
      const camera=new T.PerspectiveCamera(48,1,.1,80);camera.position.set(0,7,12);camera.lookAt(0,0,0);
      const group=new T.Group();scene.add(group);
      const geometry=new T.PlaneGeometry(22,28,32,40);geometry.rotateX(-Math.PI/2);
      const points=geometry.attributes.position;
      const base=new Float32Array(points.array);
      const material=new T.MeshBasicMaterial({color:'#ef3041',wireframe:true,transparent:true,opacity:.62});
      group.add(new T.Mesh(geometry,material));
      const dotsMaterial=new T.PointsMaterial({color:'#ff5d65',size:.065,transparent:true,opacity:.9});
      group.add(new T.Points(geometry,dotsMaterial));
      const stems:number[]=[];
      for(let i=0;i<44;i++){const x=Math.sin(i*12.989)*9,z=Math.cos(i*7.23)*12,h=.8+(i%6)*.38;stems.push(x,0,z,x,h,z);}
      const stemGeometry=new T.BufferGeometry();stemGeometry.setAttribute('position',new T.Float32BufferAttribute(stems,3));
      const stemMaterial=new T.LineBasicMaterial({color:'#e52e3e',transparent:true,opacity:.65});
      group.add(new T.LineSegments(stemGeometry,stemMaterial));
      const tipGeometry=new T.BufferGeometry();tipGeometry.setAttribute('position',new T.Float32BufferAttribute(stems.filter((_,i)=>i%6>=3),3));
      const tipMaterial=new T.PointsMaterial({color:'#ff989b',size:.12});group.add(new T.Points(tipGeometry,tipMaterial));
      let frame=0,time=0,last=0,visible=true,userPaused=false,lost=false;
      const motion=matchMedia('(prefers-reduced-motion: reduce)');
      userPaused=motion.matches;
      const render=()=>renderer.render(scene,camera);
      const tick=(now:number)=>{
        frame=0;if(disposed||userPaused||!visible||document.hidden||lost)return;
        time+=Math.min((now-last)/1000,.05);last=now;
        for(let i=0;i<points.count;i++){const x=base[i*3],z=base[i*3+2];points.setY(i,Math.sin(x*.5+time*.32)*.6+Math.cos(z*.4+time*.24)*.7);}
        points.needsUpdate=true;group.rotation.y=Math.sin(time*.12)*.15;render();frame=requestAnimationFrame(tick);
      };
      const sync=()=>{cancelAnimationFrame(frame);frame=0;if(!userPaused&&visible&&!document.hidden&&!lost){last=performance.now();frame=requestAnimationFrame(tick);}else if(!lost)render();};
      const resize=new ResizeObserver(()=>{const {width,height}=element.getBoundingClientRect();if(width&&height){renderer.setSize(width,height,false);camera.aspect=width/height;camera.updateProjectionMatrix();sync();}});resize.observe(element);
      const intersection=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;sync();});intersection.observe(element);
      const reduce=()=>{userPaused=motion.matches;sync();};
      const loss=(event:Event)=>{event.preventDefault();lost=true;cancelAnimationFrame(frame);};
      motion.addEventListener('change',reduce);document.addEventListener('visibilitychange',sync);element.addEventListener('webglcontextlost',loss);
      render();sync();
      cleanup=()=>{cancelAnimationFrame(frame);resize.disconnect();intersection.disconnect();motion.removeEventListener('change',reduce);document.removeEventListener('visibilitychange',sync);element.removeEventListener('webglcontextlost',loss);geometry.dispose();material.dispose();dotsMaterial.dispose();stemGeometry.dispose();stemMaterial.dispose();tipGeometry.dispose();tipMaterial.dispose();renderer.dispose();};
    }).catch(()=>{/* Decorative WebGL is optional; navigation remains usable. */});
    return()=>{disposed=true;cleanup();};
  },[]);
  return <div className="sidebar-field" data-ui="sidebar-3d" aria-hidden="true"><canvas ref={canvas}/></div>;
}
