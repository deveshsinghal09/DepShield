/** Navigation is connected to the existing DepShield feature routes. */
// Local copy of the existing approved hero asset; playback must not depend on a third-party CDN.
export const SECURITY_VIDEO = '/hero-motion.mp4';
export const navigationGroups = [
  { label: 'Explore', id: 'explore', children: ['Dependencies', 'Attack paths'] },
  { label: 'Remediate', id: 'remediate', children: ['Upgrade plan', 'Reports'] },
] as const;
export const destinations: Record<string,string> = {
  'Dependencies':'/dependencies', 'Attack paths':'/attack-paths',
  'Upgrade plan':'/remediation', 'Reports':'/story',
  'Scan project':'/scan', 'Scan history':'/history', 'Dashboard':'/dashboard',
};
