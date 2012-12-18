(*File CompVersionDef.inc*)

{$IFDEF VER110}
  {$DEFINE VER110__}
{$ELSE}
  {$IFDEF VER120}
    {$DEFINE VER110__}
    {$DEFINE VER120__}
  {$ELSE}
    {$IFDEF VER130}
      {$DEFINE VER110__}
      {$DEFINE VER120__}
      {$DEFINE VER130__}
    {$ELSE}
      {$IFDEF VER140}
        {$DEFINE VER110__}
        {$DEFINE VER120__}
        {$DEFINE VER130__}
        {$DEFINE VER140__}
      {$ELSE}
        {$IFDEF VER150}
          {$DEFINE VER110__}
          {$DEFINE VER120__}
          {$DEFINE VER130__}
          {$DEFINE VER140__}
          {$DEFINE VER150__}
        {$ELSE}
          {$DEFINE VER110__}
          {$DEFINE VER120__}
          {$DEFINE VER130__}
          {$DEFINE VER140__}
          {$DEFINE VER150__}
        {$ENDIF}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

