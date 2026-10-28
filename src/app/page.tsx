import { SecurityLanding } from '@/components/security/security-landing';
import { listScans } from '@/server/db';
import Dashboard from './dashboard/page';

export const dynamic = 'force-dynamic';

export default async function Home({searchParams}:{searchParams:Promise<{scan?:string}>}) {
  const params=await searchParams;
  if(params.scan!==undefined)return <Dashboard searchParams={Promise.resolve(params)}/>;
  const scans=listScans();
  const latest=scans[0];
  return <SecurityLanding summary={{scans:scans.length,score:latest?.score??null,dependencies:latest?.dependencies??null}}/>;
}
