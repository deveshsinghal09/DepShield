import {describe,it,expect} from 'vitest';
import {parseManifest,parseLockfile,extractDependencyGraph} from './dependency-tree';
describe('scan input integrity',()=>{
 it('rejects JSON that is not a lockfile',()=>expect(()=>parseLockfile('{}')).toThrow());
 it('rejects invalid manifest dependency maps',()=>expect(()=>parseManifest('{"dependencies":"lodash"}')).toThrow());
 it('rejects mismatched manifests instead of reporting zero dependencies',()=>expect(()=>extractDependencyGraph(parseManifest('{"dependencies":{"lodash":"4.17.11"}}'),parseLockfile('{"lockfileVersion":3,"packages":{"":{}}}'))).toThrow(/missing required dependency/));
 it('bounds cyclic dependency paths',()=>{
  const items=extractDependencyGraph({name:'app',dependencies:{a:'1.0.0'}},{lockfileVersion:3,packages:{'':{},'node_modules/a':{version:'1.0.0',dependencies:{b:'1.0.0'}},'node_modules/b':{version:'1.0.0',dependencies:{a:'1.0.0'}}}});
  expect(items).toHaveLength(2);expect(items.every(item=>item.paths.every(path=>path.nodes.length<=3))).toBe(true);
 });
});
