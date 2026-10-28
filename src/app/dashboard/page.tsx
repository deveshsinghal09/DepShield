import {DashboardOverview} from '@/components/dashboard/dashboard-overview';
import {EmptyState,SavedScanUnavailable} from '@/components/empty-state';
import {resolveSavedScan} from '@/server/scan-resolution';

export const dynamic='force-dynamic';
export default async function Dashboard({searchParams}:{searchParams:Promise<{scan?:string}>}){
  const {scan:id}=await searchParams;
  const {scans,resolution}=resolveSavedScan(id);
  if(resolution.status==='missing')return <SavedScanUnavailable scanId={resolution.requestedId} recoveryHref="/dashboard"/>;
  if(!resolution.scan)return <EmptyState/>;
  return <DashboardOverview scan={resolution.scan} scans={scans}/>;
}
