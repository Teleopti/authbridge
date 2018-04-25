using System;

namespace AuthBridge.Utilities
{
	public static class DateTimeUtils
	{
		public static DateTime TruncateToSecond(this DateTime dt)
		{
			return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second);
		}
	}
}