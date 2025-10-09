import { getT } from '@gitroom/react/translation/get.translation.service.backend';

export const dynamic = 'force-dynamic';
import { ReactNode } from 'react';
import Image from 'next/image';
import clsx from 'clsx';
import loadDynamic from 'next/dynamic';
import { isGeneralServerSide } from '@gitroom/helpers/utils/is.general.server.side';
const ReturnUrlComponent = loadDynamic(() => import('./return.url.component'));
export default async function AuthLayout({
  children,
}: {
  children: ReactNode;
}) {
  const t = await getT();

  return (
    <div className="dark !bg-black lbox">
      <ReturnUrlComponent />
      <div className="absolute start-0 top-0 z-[0] h-[100vh] w-[100vw] overflow-hidden bg-loginBg bg-contain bg-no-repeat bg-left-top">
        <div className="absolute inset-0 bg-gradient-to-r from-transparent to-black" />
      </div>

      <div className="relative z-[0] px-3 lg:pr-[100px] xs:mt-[70px] flex justify-center lg:justify-end items-center h-[100vh] w-[100vw] overflow-hidden">
        <div className="w-full max-w-lg h-[614px] flex flex-col bg-loginBox bg-no-repeat bg-contain">
          <div className="w-full relative">
            <div className="absolute z-10 -top-[230px] text-textColor justify-center items-center w-full flex gap-[10px]">
              <Image
                src="/logo-social.svg"
                width={450}
                height={450}
                alt="Logo"
              />

            </div>
          </div>
          <div className="p-[32px] w-full h-[660px] text-textColor rbox">
            {children}
          </div>
          <div className="flex flex-1 flex-col">
            <div className="flex-1 flex justify-end">
              <div className="absolute top-0 bg-gradient-to-t from-customColor9 w-[1px] translate-x-[22px] h-full" />
            </div>
            <div>
              <div className="absolute end-0 bg-gradient-to-l from-customColor9 h-[1px] translate-y-[60px] w-full" />
            </div>
          </div>
          <div className="absolute top-0 bg-gradient-to-t from-customColor9 w-[1px] -translate-x-[22px] h-full" />
          <div className="absolute end-0 bg-gradient-to-l from-customColor9 h-[1px] -translate-y-[22px] w-full" />
        </div>
      </div>
    </div>
  );
}
