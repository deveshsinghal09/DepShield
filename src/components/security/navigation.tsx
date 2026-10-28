import { destinations, navigationGroups } from './content';
import Link from 'next/link';
import { Chevron, SecurityButton, SecurityLogo } from './primitives';

type NavigationProps = {active:string|null;onToggle:(id:string)=>void;onSelect:(label:string)=>void;onHome:()=>void};
export function SecurityHeader({active,onToggle,onSelect,onHome}:NavigationProps) {
  return <header data-ui="site-header">
    <SecurityLogo onHome={onHome}/>
    <nav className="desktop-nav" aria-label="Primary">
      <div className="navitem"><Link href="/dashboard" className="navlink">Dashboard</Link></div>
      {navigationGroups.map(group=><div className="navitem" key={group.id}>
        <button className="navlink" aria-expanded={active===group.id} aria-controls={group.id} onClick={()=>onToggle(group.id)}>{group.label}<Chevron/></button>
        <div className="dropdown" id={group.id} hidden={active!==group.id}>{group.children.map(label=><Link key={label} href={destinations[label]}>{label}</Link>)}</div>
      </div>)}
      <div className="navitem"><Link className="navlink" href="/history">History</Link></div>
    </nav>
    <SecurityButton className="btn-top" onClick={()=>onSelect('Scan project')} />
  </header>;
}
export function MobileMenu({open,active,onToggle,onSelect,onHome,texture}:{open:boolean;texture:React.ReactNode}&NavigationProps) {
  return <div className="menu" id="security-menu" role="dialog" aria-modal="true" aria-label="Navigation menu" inert={!open} aria-hidden={!open} data-ui="mobile-navigation">
    {texture}<div className="menu-rule"/>
    <div className="menu-content"><p className="eyebrow">MENU</p><nav aria-label="Mobile">
      <div className="mitem"><Link className="mrow" href="/dashboard" onClick={onHome}>Dashboard</Link></div>
      {navigationGroups.map(group=><div className="mitem" key={group.id}>
        <button className="mrow" aria-expanded={active===group.id} aria-controls={`mobile-${group.id}`} onClick={()=>onToggle(group.id)}>{group.label}<em aria-hidden="true">{active===group.id?'−':'+'}</em></button>
        <div className="sublinks" id={`mobile-${group.id}`} hidden={active!==group.id}>{group.children.map(label=><Link key={label} href={destinations[label]} onClick={onHome}>{label}</Link>)}</div>
      </div>)}
      <div className="mitem"><Link className="mrow" href="/history" onClick={onHome}>Scan history</Link></div>
    </nav><div className="menu-footer"><SecurityButton className="btn-menu" onClick={()=>onSelect('Scan project')}/><p className="menu-note">Scan. Investigate. Remediate.</p></div></div>
  </div>;
}
