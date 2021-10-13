package br.ufsc.labsec.signature;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class SystemTime {

    private static TimeZone tz = TimeZone.getDefault();

    public static long getSystemTime() {
        GregorianCalendar gregorianCalendar = new GregorianCalendar(tz);
        return gregorianCalendar.getTimeInMillis();
    }

    public static long getTimeZoneDifference() {
        GregorianCalendar gregorianCalendar = new GregorianCalendar(tz);
        Long systemMillis = gregorianCalendar.getTimeInMillis();
        Long utcMillis = new Date().getTime();
        return systemMillis - utcMillis;
    }

}
