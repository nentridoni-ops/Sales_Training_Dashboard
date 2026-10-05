import test from 'node:test';
import assert from 'node:assert/strict';
import { createTrainingLibraryHandler } from '../lib/training-library-api.js';
import { buildDefaultAuthorizationConfig } from '../lib/permission-catalog.js';

function response() { return { statusCode: 200, headers: {}, setHeader(k,v){this.headers[k]=v;}, status(n){this.statusCode=n;return this;}, json(v){this.body=v;return this;}, end(){return this;} }; }
const material = (id, overrides={}) => ({ id, category:'iPhone', skill:'Product Knowledge', material:'iPhone Knowledge', level:'Basic', priority:1, exercise:'Practice', active:'YES', ...overrides });
function harness(role='STORE TRAINER', initial=[material('TR001')]) {
  let state={staffMaster:[{salesId:'S1'}],trainingLibrary:structuredClone(initial),imports:{},currentDate:'01-09-2026'},etag='"v1"',writes=0;
  const handler=createTrainingLibraryHandler({getSession:()=>role?{role}:null,isSameOrigin:()=>true,loadConfig:async()=>({config:buildDefaultAuthorizationConfig()}),readState:async()=>({state:structuredClone(state),etag}),writeState:async(next,expected)=>{if(expected!==etag){const e=new Error('etag');e.status=412;throw e;}state=structuredClone(next);etag='"v2"';writes++;return{etag};}});
  return {handler,state:()=>state,etag:()=>etag,writes:()=>writes};
}
async function post(h,body,etag=h.etag()){const res=response();await h.handler({method:'POST',body:{...body,expectedEtag:etag}},res);return res;}

test('Store Trainer can create and edit library materials through the granular API',async()=>{
  const h=harness();let res=await post(h,{trainingLibrary:[material('TR001'),material('TR002',{category:'Accessories',skill:'Compatibility / Cross Selling'})]});
  assert.equal(res.statusCode,200);assert.equal(h.state().trainingLibrary.length,2);assert.deepEqual(h.state().imports,{});assert.equal(res.headers.ETag,'"v2"');
  res=await post(h,{trainingLibrary:[material('TR001',{material:'Updated iPhone Knowledge'}),material('TR002',{category:'Accessories',skill:'Compatibility / Cross Selling'})]});
  assert.equal(res.statusCode,200);assert.equal(h.state().trainingLibrary[0].material,'Updated iPhone Knowledge');assert.equal(h.writes(),2);
});

test('library API enforces delete grants and denies unauthenticated or unrelated roles',async()=>{
  const h=harness();let res=await post(h,{trainingLibrary:[]});assert.equal(res.statusCode,200);
  const staff=harness('STAFF');res=await post(staff,{trainingLibrary:[material('TR001',{material:'Changed'})]});assert.equal(res.statusCode,403);assert.equal(res.body.permission,'training_library.edit');
  const anonymous=harness(null);res=await post(anonymous,{trainingLibrary:[material('TR001',{material:'Changed'})]});assert.equal(res.statusCode,401);
});

test('library API rejects invalid records, duplicate IDs, unknown fields, and stale ETags atomically',async()=>{
  const h=harness();
  for(const list of [[material('TR001'),material('TR001')],[material('TR001',{admin:true})],[material('TR001',{category:'VAS Provider'})],[material('TR001',{material:''})]]){
    const res=await post(h,{trainingLibrary:list});assert.equal(res.statusCode,400);assert.equal(h.writes(),0);
  }
  const stale=await post(h,{trainingLibrary:[material('TR001',{material:'Changed'})]},'"stale"');assert.equal(stale.statusCode,409);assert.equal(h.writes(),0);
  assert.equal(h.state().trainingLibrary[0].material,'iPhone Knowledge');
});
