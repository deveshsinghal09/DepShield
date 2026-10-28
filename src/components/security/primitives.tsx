import type { ButtonHTMLAttributes } from 'react';
import Link from 'next/link';

export function Arrow() {
  return <svg className="arrow" aria-hidden="true" viewBox="0 0 22 18" fill="none" stroke="currentColor" strokeWidth="2"><path d="M0 9H20.1M12.1 1L20.1 9L12.1 17" /></svg>;
}
export function Chevron() {
  return <svg className="chevron" aria-hidden="true" viewBox="0 0 11 6" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M1 1L5.5 5L10 1" /></svg>;
}
export function SecurityButton({className='',children='Scan project',...props}:ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button type="button" className={`btn ${className}`} {...props}><span>{children}</span><Arrow /></button>;
}
export function SecurityLogo({onHome}:{onHome:()=>void}) {
  return <Link className="logo" href="/" aria-label="DepShield home" onClick={e=>{e.preventDefault();onHome();}}><svg viewBox="0 0 46 46" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="butt" aria-hidden="true">{[0,90,180,270].map(angle=><path key={angle} d="M23 0V19.5M14 10.2L23 19.2L32 10.2" transform={`rotate(${angle} 23 23)`}/>)}</svg></Link>;
}
