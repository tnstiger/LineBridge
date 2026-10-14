// Readable text for an AI client. Only formats that parse without executing
// anything: plain-text types and PDF text layers. Scanned PDFs have no text
// layer and return none; the original bytes are still available separately.
export const TEXT_MAX_CHARS=100_000;
const TEXT_TYPES=new Set(['text/plain','text/csv','text/markdown','application/json']);

export async function extractFileText(bytes,mimeType,{timeoutMs=15000}={}){
  if(TEXT_TYPES.has(mimeType)){
    const text=new TextDecoder('utf-8',{fatal:false}).decode(bytes);
    return clip(text);
  }
  if(mimeType!=='application/pdf')return {textAvailable:false,reason:'Text extraction supports PDF text layers and plain-text files only.'};
  try{
    const {extractText,getDocumentProxy}=await import('unpdf');
    const work=(async()=>{
      // Copy: pdf.js may transfer or detach the buffer it is given.
      const pdf=await getDocumentProxy(new Uint8Array(bytes),{isEvalSupported:false,disableFontFace:true});
      try{const {totalPages,text}=await extractText(pdf,{mergePages:true});return {pages:totalPages,text};}
      finally{await pdf.destroy?.();}
    })();
    let timer;
    const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('timeout')),timeoutMs);});
    const {pages,text}=await Promise.race([work,timeout]).finally(()=>clearTimeout(timer));
    const trimmed=String(text??'').trim();
    if(!trimmed)return {textAvailable:false,pages,reason:'This PDF has no text layer (for example a scan or photo). Read the file content instead.'};
    return {...clip(trimmed),pages};
  }catch{
    return {textAvailable:false,reason:'The PDF text layer could not be read. Read the file content instead.'};
  }
}

function clip(text){
  return text.length>TEXT_MAX_CHARS?{textAvailable:true,text:text.slice(0,TEXT_MAX_CHARS),truncated:true}:{textAvailable:true,text,truncated:false};
}
