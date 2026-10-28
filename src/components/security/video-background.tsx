import type { RefObject } from 'react';
import { SECURITY_VIDEO } from './content';
import grades from './video-grade.json';

export function VideoGrades() {
  return <svg className="svgdefs" aria-hidden="true"><defs>{grades.map(grade=><filter key={grade.id} id={grade.id} colorInterpolationFilters="sRGB"><feComponentTransfer><feFuncR type="table" tableValues={grade.channels[0]}/><feFuncG type="table" tableValues={grade.channels[1]}/><feFuncB type="table" tableValues={grade.channels[2]}/></feComponentTransfer></filter>)}</defs></svg>;
}
export function VideoPlate({className,videoRef}:{className:string;videoRef:RefObject<HTMLVideoElement|null>}) {
  // Retry on readiness: an early play request can be interrupted by hydration or effect cleanup.
  return <div className={className} aria-hidden="true"><video ref={videoRef} src={SECURITY_VIDEO} autoPlay muted loop playsInline preload="auto" onCanPlay={event=>{
    const video=event.currentTarget;
    if(document.hidden || matchMedia('(prefers-reduced-motion: reduce)').matches)return;
    video.muted=true;
    void video.play().catch(()=>{});
  }} /></div>;
}
